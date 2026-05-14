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

  if (!Array.isArray(license.deviceIDs)) {
    license.deviceIDs = license.deviceID ? [license.deviceID] : [];
  }

  if (!license.maxDevices || Number(license.maxDevices) < 1) {
    license.maxDevices = 1;
  }

  if (!license.deviceIDs.includes(deviceID)) {
    if (license.deviceIDs.length >= Number(license.maxDevices)) {
      return res.json({
        valid: false,
        expiresAt: 0,
        message: `Giấy phép này đã đủ ${license.maxDevices} máy sử dụng`
      });
    }

    license.deviceIDs.push(deviceID);
  }

  license.deviceID = license.deviceIDs[0] || "";

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

function createLicenseHandler(req, res) {
  const { adminToken, licenseKey, days, maxDevices } = req.body;

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
    deviceIDs: [],
    maxDevices: Math.max(1, Number(maxDevices || 1)),
    createdAt: now,
    lastCheckAt: 0,
    lastAction: "",
    lastAppVersion: ""
  };

  saveDB(db);

  return res.json({
    ok: true,
    valid: true,
    licenseKey: key,
    expiresAt: db.licenses[key].expiresAt,
    message: `Đã tạo license ${days} ngày`
  });
}

app.post("/admin/create", createLicenseHandler);
app.post("/api/admin/create-license", createLicenseHandler);

app.get("/admin", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PluginLocker License Admin</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0f1115; color: #f5f5f5; }
    header { padding: 22px 28px; border-bottom: 1px solid #282c35; background: #151820; position: sticky; top: 0; z-index: 10; }
    h1 { margin: 0; font-size: 24px; }
    main { padding: 24px 28px 40px; max-width: 1500px; margin: 0 auto; }
    .grid { display: grid; grid-template-columns: 360px minmax(900px, 1fr); gap: 18px; align-items: start; }
    .card { background: #171a22; border: 1px solid #2a2f3a; border-radius: 14px; padding: 16px; box-shadow: 0 10px 28px rgba(0,0,0,.25); }
    label { display: block; font-size: 12px; color: #a8b0c0; margin: 10px 0 6px; }
    input, button { font: inherit; }
    input { width: 100%; box-sizing: border-box; border: 1px solid #333a48; border-radius: 10px; padding: 10px 12px; background: #0f1117; color: #fff; outline: none; }
    input:focus { border-color: #6ea8ff; }
    button { border: 0; border-radius: 10px; padding: 9px 12px; background: #3b82f6; color: white; cursor: pointer; font-weight: 650; }
    button.secondary { background: #374151; }
    button.warning { background: #d97706; }
    button.danger { background: #dc2626; }
    button.green { background: #16a34a; }
    .row { display: flex; gap: 8px; align-items: center; }
    .row > * { flex: 1; }
    .toolbar { display: flex; gap: 10px; align-items: center; justify-content: space-between; margin-bottom: 12px; }
    .toolbar input { max-width: 360px; }
    table { width: 100%; min-width: 1050px; border-collapse: separate; border-spacing: 0; table-layout: fixed; }
    th, td { padding: 14px 10px; border-bottom: 1px solid #292f3a; text-align: left; vertical-align: top; font-size: 13px; line-height: 1.45; overflow-wrap: anywhere; }
    th { color: #a8b0c0; background: #11141b; position: static; z-index: auto; }
    tr:hover td { background: #1c2130; }
    .pill { display: inline-block; border-radius: 999px; padding: 3px 8px; font-size: 12px; font-weight: 700; }
    .ok { background: rgba(22,163,74,.18); color: #4ade80; }
    .bad { background: rgba(220,38,38,.18); color: #f87171; }
    .warn { background: rgba(217,119,6,.18); color: #fbbf24; }
    .muted { color: #8b94a7; font-size: 12px; }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; min-width: 230px; }
    pre { white-space: pre-wrap; word-break: break-word; background: #0f1117; border: 1px solid #2a2f3a; border-radius: 10px; padding: 10px; min-height: 40px; max-height: 260px; overflow: auto; color: #cbd5e1; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } th { position: static; } }
  </style>
</head>
<body>
  <header>
    <h1>PluginLocker License Admin</h1>
    <div class="muted">Quản lý giấy phép, máy kích hoạt, thời hạn và trạng thái khóa.</div>
  </header>

  <main>
    <div class="grid">
      <section class="card">
        <h2>Tạo / gia hạn license</h2>

        <label>Admin token</label>
        <input id="adminToken" type="password" placeholder="Nhập admin token" autocomplete="off" />

        <label>License key</label>
        <input id="licenseKey" placeholder="PL-USER-30DAYS-001" />

        <label>Số ngày</label>
        <input id="days" type="number" min="1" step="1" value="30" />

        <label>Số máy tối đa</label>
        <input id="maxDevices" type="number" min="1" step="1" value="1" />

        <div class="row" style="margin-top:12px">
          <button onclick="createLicense()">Tạo / Gia hạn</button>
          <button class="secondary" onclick="makeRandomKey()">Random key</button>
        </div>

        <div class="row" style="margin-top:8px">
          <button class="secondary" onclick="saveToken()">Lưu token</button>
          <button class="secondary" onclick="loadLicenses()">Tải lại</button>
        </div>

        <h3>Kết quả</h3>
        <pre id="resultBox">Chưa có thao tác.</pre>
      </section>

      <section class="card">
        <div class="toolbar">
          <h2 style="margin:0">Danh sách license</h2>
          <input id="searchBox" placeholder="Tìm license / device / appVersion" oninput="renderTable()" />
        </div>

        <div class="muted" id="summaryText">Chưa tải dữ liệu.</div>

        <div style="overflow-x:auto; overflow-y:visible; margin-top:12px; padding-bottom:8px">
          <table>
            <thead>
              <tr>
                <th style="width:200px">License</th>
                <th style="width:110px">Trạng thái</th>
                <th style="width:270px">Máy đang dùng</th>
                <th style="width:160px">Thời hạn</th>
                <th style="width:170px">Lần cuối</th>
                <th style="width:250px">Thao tác</th>
              </tr>
            </thead>
            <tbody id="licenseRows"></tbody>
          </table>
        </div>
      </section>
    </div>
  </main>

  <script>
    let licenses = [];

    const $ = (id) => document.getElementById(id);

    function getToken() {
      return $("adminToken").value.trim();
    }

    function saveToken() {
      localStorage.setItem("pluginlockerAdminToken", getToken());
      showResult({ ok: true, message: "Đã lưu token trong trình duyệt này." });
    }

    function restoreToken() {
      $("adminToken").value = localStorage.getItem("pluginlockerAdminToken") || "";
    }

    function showResult(obj) {
      $("resultBox").textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
    }

    function makeRandomKey() {
      const date = new Date().toISOString().slice(0,10).replaceAll("-", "");
      const rand = Math.random().toString(16).slice(2, 10).toUpperCase();
      $("licenseKey").value = "PL-" + date + "-" + rand;
    }

    async function api(path, body) {
      const res = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      const text = await res.text();
      let data;

      try {
        data = JSON.parse(text);
      } catch {
        data = { ok: false, message: text };
      }

      if (!res.ok) {
        throw data;
      }

      return data;
    }

    async function createLicense() {
      try {
        const payload = {
          adminToken: getToken(),
          licenseKey: $("licenseKey").value.trim().toUpperCase(),
          days: Number($("days").value || 30),
          maxDevices: Number($("maxDevices").value || 1)
        };

        const data = await api("/api/admin/create-license", payload);
        showResult(data);
        await loadLicenses();
      } catch (e) {
        showResult(e);
      }
    }

    async function loadLicenses() {
      try {
        const token = encodeURIComponent(getToken());
        const res = await fetch("/api/admin/licenses?adminToken=" + token);
        const data = await res.json();

        if (!res.ok) {
          throw data;
        }

        licenses = data.licenses || [];
        showResult(data);
        renderTable();
      } catch (e) {
        showResult(e);
      }
    }

    async function adminAction(action, licenseKey) {
      try {
        const data = await api("/api/admin/" + action, {
          adminToken: getToken(),
          licenseKey
        });

        showResult(data);
        await loadLicenses();
      } catch (e) {
        showResult(e);
      }
    }

    function formatDate(seconds) {
      if (!seconds) return "-";
      return new Date(seconds * 1000).toLocaleString();
    }

    function statusFor(item) {
      const now = Math.floor(Date.now() / 1000);

      if (item.revoked) {
        return '<span class="pill bad">Đã khóa</span>';
      }

      if (!item.expiresAt || item.expiresAt < now) {
        return '<span class="pill warn">Hết hạn</span>';
      }

      return '<span class="pill ok">Hoạt động</span>';
    }

    function remainingText(item) {
      const now = Math.floor(Date.now() / 1000);
      const seconds = Math.max(0, (item.expiresAt || 0) - now);
      const days = Math.ceil(seconds / 86400);

      if (!seconds) return "Đã hết hạn";
      return days >= 1 ? "Còn khoảng " + days + " ngày" : "Còn dưới 1 ngày";
    }

    function escapeText(value) {
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }

    function renderTable() {
      const q = $("searchBox").value.trim().toLowerCase();
      const filtered = licenses.filter(item => JSON.stringify(item).toLowerCase().includes(q));

      $("summaryText").textContent = "Tổng " + licenses.length + " license, đang hiển thị " + filtered.length + ".";

      $("licenseRows").innerHTML = filtered.map(item => {
        const key = item.licenseKey || "";
        const revoked = !!item.revoked;

        return '<tr>' +
          '<td><b>' + escapeText(key) + '</b><div class="muted">created: ' + escapeText(formatDate(item.createdAt)) + '</div></td>' +
          '<td>' + statusFor(item) + '</td>' +
          '<td><div style="white-space:pre-line">' + escapeText((item.deviceIDs && item.deviceIDs.length ? item.deviceIDs.join("\n") : (item.deviceID || "Chưa gắn máy"))) + '</div><div class="muted">' + escapeText((item.deviceIDs ? item.deviceIDs.length : (item.deviceID ? 1 : 0)) + "/" + (item.maxDevices || 1)) + ' máy</div><div class="muted">app: ' + escapeText(item.lastAppVersion || "-") + '</div></td>' +
          '<td><div>' + escapeText(remainingText(item)) + '</div><div class="muted">' + escapeText(formatDate(item.expiresAt)) + '</div></td>' +
          '<td><div>' + escapeText(formatDate(item.lastCheckAt)) + '</div><div class="muted">action: ' + escapeText(item.lastAction || "-") + '</div></td>' +
          '<td class="actions">' +
            '<button class="secondary" onclick="adminAction(\\'reset-device\\', \\'' + escapeText(key) + '\\')">Reset máy</button>' +
            '<button class="' + (revoked ? "green" : "warning") + '" onclick="adminAction(\\'' + (revoked ? "unrevoke" : "revoke") + '\\', \\'' + escapeText(key) + '\\')">' + (revoked ? "Mở khóa" : "Khóa") + '</button>' +
            '<button class="danger" onclick="confirm(\\'Xóa license ' + escapeText(key) + '?\\') && adminAction(\\'delete-license\\', \\'' + escapeText(key) + '\\')">Xóa</button>' +
          '</td>' +
        '</tr>';
      }).join("");
    }

    restoreToken();
    loadLicenses();
  </script>
</body>
</html>`);
});
app.get("/api/admin/licenses", (req, res) => {
  const { adminToken } = req.query;

  if (adminToken !== ADMIN_TOKEN) {
    return res.status(403).json({ ok: false, message: "Sai admin token" });
  }

  const db = loadDB();
  const licenses = Object.values(db.licenses || {}).sort((a, b) =>
    String(a.licenseKey).localeCompare(String(b.licenseKey))
  );

  return res.json({ ok: true, licenses });
});

function requireAdminToken(req, res) {
  const { adminToken, licenseKey } = req.body;

  if (adminToken !== ADMIN_TOKEN) {
    res.status(403).json({ ok: false, message: "Sai admin token" });
    return null;
  }

  if (!licenseKey) {
    res.status(400).json({ ok: false, message: "Thiếu licenseKey" });
    return null;
  }

  const db = loadDB();
  const key = String(licenseKey).toUpperCase();

  if (!db.licenses || !db.licenses[key]) {
    res.status(404).json({ ok: false, message: "License không tồn tại" });
    return null;
  }

  return { db, key };
}

app.post("/api/admin/reset-device", (req, res) => {
  const result = requireAdminToken(req, res);
  if (!result) return;

  const { db, key } = result;

  db.licenses[key].deviceID = "";
  db.licenses[key].deviceIDs = [];
  db.licenses[key].lastAction = "reset-device";
  db.licenses[key].lastCheckAt = nowSeconds();

  saveDB(db);

  return res.json({
    ok: true,
    message: "Đã reset máy đang dùng license",
    license: db.licenses[key]
  });
});

app.post("/api/admin/revoke", (req, res) => {
  const result = requireAdminToken(req, res);
  if (!result) return;

  const { db, key } = result;

  db.licenses[key].revoked = true;
  db.licenses[key].lastAction = "revoke";
  db.licenses[key].lastCheckAt = nowSeconds();

  saveDB(db);

  return res.json({
    ok: true,
    message: "Đã khóa license",
    license: db.licenses[key]
  });
});

app.post("/api/admin/unrevoke", (req, res) => {
  const result = requireAdminToken(req, res);
  if (!result) return;

  const { db, key } = result;

  db.licenses[key].revoked = false;
  db.licenses[key].lastAction = "unrevoke";
  db.licenses[key].lastCheckAt = nowSeconds();

  saveDB(db);

  return res.json({
    ok: true,
    message: "Đã mở khóa license",
    license: db.licenses[key]
  });
});

app.post("/api/admin/delete-license", (req, res) => {
  const result = requireAdminToken(req, res);
  if (!result) return;

  const { db, key } = result;

  delete db.licenses[key];
  saveDB(db);

  return res.json({
    ok: true,
    message: "Đã xóa license",
    licenseKey: key
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
  license.deviceIDs = [];
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