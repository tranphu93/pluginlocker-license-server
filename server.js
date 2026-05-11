const express = require("express");
const cors = require("cors");
const fs = require("fs");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || "./licenses.json";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "phutran-admin-123";

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ licenses: {} }, null, 2));
  }

  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

app.get("/", (req, res) => {
  res.send("PluginLocker license server is running.");
});

app.get("/healthz", (req, res) => {
  res.json({ ok: true, time: nowSeconds() });
});

app.post("/api/license", (req, res) => {
  const { licenseKey, deviceID, appVersion, action } = req.body;

  if (!licenseKey || !deviceID) {
    return res.status(400).json({
      valid: false,
      expiresAt: 0,
      message: "Thiếu licenseKey hoặc deviceID"
    });
  }

  const db = loadDB();
  const key = String(licenseKey).toUpperCase();
  const license = db.licenses[key];

  if (!license) {
    return res.json({
      valid: false,
      expiresAt: 0,
      message: "Giấy phép không tồn tại"
    });
  }

  if (license.revoked) {
    return res.json({
      valid: false,
      expiresAt: 0,
      message: "Giấy phép đã bị admin chấm dứt"
    });
  }

  const now = nowSeconds();

  if (license.expiresAt <= now) {
    return res.json({
      valid: false,
      expiresAt: license.expiresAt,
      message: "Giấy phép đã hết hạn"
    });
  }

  if (!license.deviceID) {
    license.deviceID = deviceID;
  }

  if (license.deviceID !== deviceID) {
    return res.json({
      valid: false,
      expiresAt: 0,
      message: "Giấy phép này đang được dùng trên máy khác"
    });
  }

  license.lastCheckAt = now;
  license.lastAction = action || "check";
  license.lastAppVersion = appVersion || "";
  saveDB(db);

  return res.json({
    valid: true,
    expiresAt: license.expiresAt,
    message: "Giấy phép đang hoạt động"
  });
});

app.post("/admin/create", (req, res) => {
  const { adminToken, licenseKey, days } = req.body;

  if (adminToken !== ADMIN_TOKEN) {
    return res.status(403).json({ ok: false, message: "Sai admin token" });
  }

  if (!licenseKey || !days) {
    return res.status(400).json({
      ok: false,
      message: "Thiếu licenseKey hoặc days"
    });
  }

  const db = loadDB();
  const key = String(licenseKey).toUpperCase();
  const now = nowSeconds();

  db.licenses[key] = {
    licenseKey: key,
    expiresAt: now + Number(days) * 24 * 60 * 60,
    revoked: false,
    deviceID: "",
    createdAt: now,
    lastCheckAt: 0,
    lastAction: "",
    lastAppVersion: ""
  };

  saveDB(db);

  res.json({
    ok: true,
    licenseKey: key,
    expiresAt: db.licenses[key].expiresAt,
    message: `Đã tạo license ${days} ngày`
  });
});

app.post("/admin/extend", (req, res) => {
  const { adminToken, licenseKey, days } = req.body;

  if (adminToken !== ADMIN_TOKEN) {
    return res.status(403).json({ ok: false, message: "Sai admin token" });
  }

  const db = loadDB();
  const key = String(licenseKey).toUpperCase();
  const license = db.licenses[key];

  if (!license) {
    return res.status(404).json({
      ok: false,
      message: "Không tìm thấy license"
    });
  }

  const now = nowSeconds();
  const baseTime = Math.max(now, license.expiresAt);

  license.expiresAt = baseTime + Number(days) * 24 * 60 * 60;
  license.revoked = false;
  saveDB(db);

  res.json({
    ok: true,
    licenseKey: key,
    expiresAt: license.expiresAt,
    message: `Đã gia hạn thêm ${days} ngày`
  });
});

app.post("/admin/revoke", (req, res) => {
  const { adminToken, licenseKey } = req.body;

  if (adminToken !== ADMIN_TOKEN) {
    return res.status(403).json({ ok: false, message: "Sai admin token" });
  }

  const db = loadDB();
  const key = String(licenseKey).toUpperCase();
  const license = db.licenses[key];

  if (!license) {
    return res.status(404).json({
      ok: false,
      message: "Không tìm thấy license"
    });
  }

  license.revoked = true;
  saveDB(db);

  res.json({
    ok: true,
    licenseKey: key,
    message: "Đã chấm dứt license"
  });
});

app.post("/admin/reset-device", (req, res) => {
  const { adminToken, licenseKey } = req.body;

  if (adminToken !== ADMIN_TOKEN) {
    return res.status(403).json({ ok: false, message: "Sai admin token" });
  }

  const db = loadDB();
  const key = String(licenseKey).toUpperCase();
  const license = db.licenses[key];

  if (!license) {
    return res.status(404).json({
      ok: false,
      message: "Không tìm thấy license"
    });
  }

  license.deviceID = "";
  saveDB(db);

  res.json({
    ok: true,
    licenseKey: key,
    message: "Đã reset máy đang dùng license"
  });
});

app.post("/admin/list", (req, res) => {
  const { adminToken } = req.body;

  if (adminToken !== ADMIN_TOKEN) {
    return res.status(403).json({ ok: false, message: "Sai admin token" });
  }

  const db = loadDB();

  res.json({
    ok: true,
    licenses: db.licenses
  });
});

app.listen(PORT, () => {
  console.log(`PluginLocker license server running on port ${PORT}`);
});