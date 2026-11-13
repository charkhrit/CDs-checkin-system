"use strict";
/**
 * export-encrypt.js
 * ดึงข้อมูลจาก Google Apps Script (GAS) -> เข้ารหัส AES-256-GCM -> บันทึกเป็น data.json
 *
 * Required environment:
 *   GAS_EXPORTER_URL   URL ของ GAS Web App (หรือ Deployment ID)
 *   MASTER_PASSPHRASE  รหัสผ่านสำหรับเข้ารหัส
 *
 * Optional token secrets (first non-empty value wins):
 *   GAS_EXPORTER_TOKEN, SECRET_TOKEN, GAS_SECRET_TOKEN, GAS_TOKEN
 * If a token secret is supplied, it replaces the URL's `token` query parameter.
 * Otherwise, GAS_EXPORTER_URL must already contain `?token=...`.
 *
 * Optional:
 *   OUTPUT_FILE        ชื่อไฟล์ผลลัพธ์ (ค่าเริ่มต้น data.json)
 */

const crypto = require("crypto");
const fs = require("fs");
const https = require("https");

const OUTPUT_FILE = process.env.OUTPUT_FILE || "data.json";
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
  for (const name of ["GAS_EXPORTER_TOKEN", "SECRET_TOKEN", "GAS_SECRET_TOKEN", "GAS_TOKEN"]) {
    const token = clean(process.env[name]);
    if (token) return token;
  }
  return "";
}

function validateConfig() {
  const rawUrl = clean(process.env.GAS_EXPORTER_URL);
  const password = clean(process.env.MASTER_PASSPHRASE);
  const token = getTokenFromEnv();

  if (!rawUrl) fail("GAS_EXPORTER_URL ว่าง - ตรวจ Repository Secret และการส่งค่า env ใน workflow");
  if (!password) fail("MASTER_PASSPHRASE ว่าง - ตรวจ Repository Secret และการส่งค่า env ใน workflow");

  let normalized = rawUrl;
  if (/^script\.google\.com\//i.test(normalized)) {
    normalized = "https://" + normalized;
  } else if (!/^https?:\/\//i.test(normalized) && /^[A-Za-z0-9_-]{20,}$/.test(normalized)) {
    normalized = "https://script.google.com/macros/s/" + normalized + "/exec";
  }

  let url;
  try {
    url = new URL(normalized);
  } catch {
    fail("GAS_EXPORTER_URL ไม่ใช่ URL ที่ถูกต้อง (ใช้ URL เต็มของ Web App หรือ Deployment ID)");
  }

  if (url.protocol !== "https:") fail("GAS_EXPORTER_URL ต้องเป็น https:// เท่านั้น");
  if (!/(^|\.)google(usercontent)?\.com$/.test(url.hostname)) {
    fail("GAS_EXPORTER_URL ต้องเป็นโดเมนของ Google Apps Script (script.google.com)");
  }

  // ถ้าระบุ token secret ให้ใช้ค่านั้นเป็นค่าหลัก เพื่อป้องกัน URL มี token เก่าหรือไม่ตรงกัน
  if (token) url.searchParams.set("token", token);
  if (!url.searchParams.get("token")) {
    fail("ไม่พบ token: เพิ่ม ?token=... ใน GAS_EXPORTER_URL หรือกำหนด Secret GAS_EXPORTER_TOKEN");
  }

  return { url: url.href, password };
}

function fetchOnce(target, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > MAX_REDIRECTS) {
      return reject(Object.assign(new Error("redirect เกิน " + MAX_REDIRECTS + " ครั้ง"), { fatal: true }));
    }

    const req = https.get(target, {
      headers: {
        "User-Agent": "export-encrypt/1.0",
        Accept: "application/json, text/plain, */*",
      },
    }, (res) => {
      const code = res.statusCode || 0;

      if (code >= 300 && code < 400 && res.headers.location) {
        res.resume();
        let next;
        try {
          next = new URL(res.headers.location, target);
          if (next.protocol !== "https:") throw new Error("redirect ต้องเป็น HTTPS");
        } catch {
          return reject(Object.assign(new Error("Location header ไม่ถูกต้องหรือไม่ปลอดภัย"), { fatal: true }));
        }
        return resolve(fetchOnce(next.href, redirects + 1));
      }

      if (code !== 200) {
        res.resume();
        const retryable = code >= 500 || code === 429;
        return reject(Object.assign(new Error("HTTP " + code), { fatal: !retryable }));
      }

      const chunks = [];
      let size = 0;
      res.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_BYTES) {
          req.destroy(Object.assign(new Error("ข้อมูลใหญ่เกิน " + MAX_BYTES + " bytes"), { fatal: true }));
          return;
        }
        chunks.push(chunk);
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
      await new Promise((resolve) => setTimeout(resolve, wait));
    }
  }
  throw lastErr;
}

function validatePayload(text) {
  const body = text.replace(/^\uFEFF/, "").trim();
  if (!body) fail("GAS ตอบกลับมาเป็นค่าว่าง");
  if (/^<(!doctype|html)/i.test(body)) {
    fail("GAS ตอบกลับเป็นหน้า HTML (อาจเป็นหน้า login/error) - ตรวจการ Deploy และสิทธิ์ Web App");
  }

  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    fail("ข้อมูลจาก GAS ไม่ใช่ JSON ที่ถูกต้อง - ตรวจ URL และรูปแบบคำตอบจาก Apps Script");
  }

  // อย่าเข้ารหัสข้อความ error เป็น data.json ที่ดูเหมือนสำเร็จ
  if (parsed && !Array.isArray(parsed) && parsed.error) {
    fail("GAS ปฏิเสธคำขอ: " + String(parsed.error) + " - ตรวจว่า token ตรงกับ SECRET_TOKEN ใน Apps Script และ Web App อนุญาตให้เรียกใช้งาน");
  }
  if (!Array.isArray(parsed)) {
    fail("ข้อมูลจาก GAS ไม่ใช่รายการ (array) ตามรูปแบบที่หน้าเว็บต้องการ");
  }
  if (parsed.length === 0) console.warn("WARN: ข้อมูลจาก GAS เป็นรายการว่าง");

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
  console.log("กำลังดึงข้อมูลจาก Google Apps Script ...");

  const body = validatePayload(await fetchWithRetry(url));
  console.log("ได้ข้อมูล " + Buffer.byteLength(body, "utf8") + " bytes");

  const payload = encrypt(body, password);
  if (!verify(payload, password, body)) fail("ตรวจสอบถอดรหัสไม่ผ่าน - ไม่เขียนไฟล์");

  writeAtomic(OUTPUT_FILE, JSON.stringify(payload));
  console.log("Encryption and data save successful.");
}

main().catch((err) => fail(err && err.message ? err.message : String(err)));
