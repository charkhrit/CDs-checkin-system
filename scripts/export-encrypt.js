"use strict";
/**
 * export-encrypt.js
 * ดึงข้อมูลจาก Google Apps Script (GAS) -> เข้ารหัส AES-256-GCM -> บันทึกเป็น data.json
 *
 * ต้องมี env:
 *   GAS_EXPORTER_URL   URL เต็มของ Web App (https://script.google.com/macros/s/.../exec)
 *   MASTER_PASSPHRASE  รหัสผ่านสำหรับเข้ารหัส
 *
 * env เสริม (ไม่ใส่ก็ได้):
 *   OUTPUT_FILE        ชื่อไฟล์ผลลัพธ์ (ค่าเริ่มต้น data.json)
 *   EXPECT_JSON        ตั้งเป็น "false" ถ้าข้อมูลจาก GAS ไม่ใช่ JSON
 *
 * หาก GAS_EXPORTER_URL ยังไม่มี ?token=... ให้ระบุ secret อย่างใดอย่างหนึ่งต่อไปนี้:
 *   GAS_EXPORTER_TOKEN, SECRET_TOKEN, GAS_SECRET_TOKEN, GAS_TOKEN
 */

const crypto = require("crypto");
const fs = require("fs");
const https = require("https");

const OUTPUT_FILE = process.env.OUTPUT_FILE || "data.json";
const EXPECT_JSON = (process.env.EXPECT_JSON || "true").toLowerCase() !== "false";
const MAX_REDIRECTS = 10;
const MAX_RETRIES = 3;
const TIMEOUT_MS = 30000;
const MAX_BYTES = 50 * 1024 * 1024;
const PBKDF2_ITERATIONS = 100000;

function fail(msg) {
  console.error("ERROR: " + msg);
  process.exit(1);
}

function clean(value) {
  let v = String(value || "").replace(/^\uFEFF/, "").trim();
  if (v.length >= 2 && ((v[0] === '"' && v.at(-1) === '"') || (v[0] === "'" && v.at(-1) === "'"))) {
    v = v.slice(1, -1).trim();
  }
  return v;
}

function getTokenFromEnv() {
  const keys = ["GAS_EXPORTER_TOKEN", "SECRET_TOKEN", "GAS_SECRET_TOKEN", "GAS_TOKEN"];
  for (const key of keys) {
    const token = clean(process.env[key]);
    if (token) return token;
  }
  return "";
}

function validateConfig() {
  const rawUrl = clean(process.env.GAS_EXPORTER_URL);
  const password = clean(process.env.MASTER_PASSPHRASE);
  const token = getTokenFromEnv();

  if (!rawUrl) fail("GAS_EXPORTER_URL ว่าง - ตรวจชื่อและค่า Secret ใ�� Settings > Secrets and variables > Actions (และ workflow ต้องส่งผ่าน env)");
  if (!password) fail("MASTER_PASSPHRASE ว่าง - ตรวจ Secret และการส่งค่าผ่าน env ใน workflow");

  let normalized = rawUrl;
  if (!/^https?:\/\//i.test(normalized)) {
    if (/^script\.google\.com\//i.test(normalized)) {
      normalized = "https://" + normalized;
    } else if (/^[A-Za-z0-9_-]{20,}$/.test(normalized)) {
      normalized = "https://script.google.com/macros/s/" + normalized + "/exec";
    } else {
      normalized = "https://" + normalized;
    }
  }

  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    fail("GAS_EXPORTER_URL ไม่ใช่ URL ที่ถูกต้อง (ต้องขึ้นต้นด้วย https:// และเป็น URL เต็มของ Web App ของ Google Apps Script)");
  }

  if (parsed.protocol !== "https:") fail("GAS_EXPORTER_URL ต้องเป็น https:// เท่านั้น");
  if (!/(^|\.)google(usercontent)?\.com$/.test(parsed.hostname)) {
    console.warn("WARN: โดเมน " + parsed.hostname + " ไม่ใช่ของ Google - ตรวจสอบว่าตั้งค่า URL ถูกต้อง");
  }

  if (!parsed.searchParams.has("token") && !parsed.searchParams.has("key") && token) {
    parsed.searchParams.set("token", token);
  }

  if (!parsed.searchParams.has("token") && !parsed.searchParams.has("key")) {
    fail("GAS_EXPORTER_URL ต้องมี ?token=... หรือกำหนด secret ชื่อ GAS_EXPORTER_TOKEN / SECRET_TOKEN / GAS_SECRET_TOKEN / GAS_TOKEN");
  }

  return { url: parsed.href, password };
}

function fetchOnce(target, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > MAX_REDIRECTS) return reject(Object.assign(new Error("redirect เกิน " + MAX_REDIRECTS + " ครั้ง"), { fatal: true }));

    const req = https.get(target, { headers: { "User-Agent": "export-encrypt/1.0", Accept: "application/json, text/plain, */*" } }, (res) => {
      const code = res.statusCode || 0;

      if (code >= 300 && code < 400 && res.headers.location) {
        res.resume();
        let next;
        try {
          next = new URL(res.headers.location, target).href;
        } catch {
          return reject(Object.assign(new Error("Location header ไม่ถูกต้อง"), { fatal: true }));
        }
        return resolve(fetchOnce(next, redirects + 1));
      }

      if (code !== 200) {
        res.resume();
        const retryable = code >= 500 || code === 429;
        return reject(Object.assign(new Error("HTTP " + code), { fatal: !retryable }));
      }

      const chunks = [];
      let size = 0;
      res.on("data", (c) => {
        size += c.length;
        if (size > MAX_BYTES) {
          req.destroy(Object.assign(new Error("ข้อมูลใหญ่เกิน " + MAX_BYTES + " bytes"), { fatal: true }));
          return;
        }
        chunks.push(c);
      });
      res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      res.on("error", reject);
    });

    req.setTimeout(TIMEOUT_MS, () => req.destroy(new Error("timeout หลัง " + TIMEOUT_MS / 1000 + " วินาที")));
    req.on("error", reject);
  });
}

async function fetchWithRetry(url) {
  let lastErr;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await fetchOnce(url);
    } catch (err) {
      lastErr = err;
      if (err.fatal || attempt === MAX_RETRIES) break;
      const wait = 2000 * attempt;
      console.warn("ครั้งที่ " + attempt + " ล้มเหลว (" + err.message + ") - ลองใหม่ใน " + wait / 1000 + " วินาที");
      await new Promise((r) => setTimeout(r, wait));
    }
  }
  throw lastErr;
}

function validatePayload(text) {
  const body = text.replace(/^\uFEFF/, "").trim();
  if (!body) fail("GAS ตอบกลับมาเป็นค่าว่าง");

  if (/^<(!doctype|html)/i.test(body)) {
    fail("GAS ตอบกลับเป็นหน้า HTML (น่าจะเป็นหน้า login หรือหน้า error ของ Google) - ตรวจว่า Deploy เป็น Web App และตั้ง Who has access เป็น Anyone");
  }

  if (EXPECT_JSON) {
    try {
      JSON.parse(body);
    } catch {
      fail("ข้อมูลจาก GAS ไม่ใช่ JSON ที่ถูกต้อง (ถ้าตั้งใจให้เป็นข้อความธรรมดา ให้ตั้ง EXPECT_JSON=false)");
    }
  }
  return body;
}

function encrypt(plain, password) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, "sha256");
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let ciphertext = cipher.update(plain, "utf8", "hex");
  ciphertext += cipher.final("hex");
  return {
    salt: salt.toString("hex"),
    iv: iv.toString("hex"),
    authTag: cipher.getAuthTag().toString("hex"),
    ciphertext,
  };
}

function verify(payload, password, expected) {
  const key = crypto.pbkdf2Sync(password, Buffer.from(payload.salt, "hex"), PBKDF2_ITERATIONS, 32, "sha256");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(payload.iv, "hex"));
  decipher.setAuthTag(Buffer.from(payload.authTag, "hex"));
  let out = decipher.update(payload.ciphertext, "hex", "utf8");
  out += decipher.final("utf8");
  return out === expected;
}

function writeAtomic(file, content) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, content);
  fs.renameSync(tmp, file);
}

async function main() {
  const { url, password } = validateConfig();
  console.log("กำลังดึงข้อมูลจาก " + new URL(url).hostname + " ...");

  const raw = await fetchWithRetry(url);
  const body = validatePayload(raw);
  console.log("ได้ข้อมูล " + Buffer.byteLength(body, "utf8") + " bytes");

  const payload = encrypt(body, password);
  if (!verify(payload, password, body)) fail("ตรวจสอบถอดรหัสไม่ผ่าน - ไม่เขียนไฟล์");

  writeAtomic(OUTPUT_FILE, JSON.stringify(payload));
  console.log("Encryption and data save successful.");
}

main().catch((err) => fail(err && err.message ? err.message : String(err)));
