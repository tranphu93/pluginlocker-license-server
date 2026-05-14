const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "phutran-admin-123";

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.warn("DATABASE_URL is not set. The server needs it to connect to Supabase/PostgreSQL.");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function normalizeKey(value) {
  return String(value || "").trim().toUpperCase();
}

function normalizeLicense(row) {
  if (!row) return null;

  let deviceIDs = row.device_ids;
  if (!Array.isArray(deviceIDs)) {
    deviceIDs = row.device_id ? [row.device_id] : [];
  }

  return {
    licenseKey: row.license_key,
    expiresAt: Number(row.expires_at || 0),
    revoked: !!row.revoked,
    deviceID: row.device_id || "",
    deviceIDs,
    maxDevices: Math.max(1, Number(row.max_devices || 1)),
    createdAt: Number(row.created_at || 0),
    lastCheckAt: Number(row.last_check_at || 0),
    lastAction: row.last_action || "",
    lastAppVersion: row.last_app_version || ""
  };
}

async function ensureSchema() {
  await pool.query(`
    create table if not exists licenses (
      license_key text primary key,
      expires_at bigint not null,
      revoked boolean not null default false,
      device_id text not null default '',
      device_ids jsonb not null default '[]'::jsonb,
      max_devices integer not null default 1,
      created_at bigint not null,
      last_check_at bigint not null default 0,
      last_action text not null default '',
      last_app_version text not null default ''
    )
  `);
}

async function getLicense(key) {
  const result = await pool.query("select * from licenses where license_key = $1", [key]);
  return normalizeLicense(result.rows[0]);
}

async function listLicenses() {
  const result = await pool.query("select * from licenses order by license_key asc");
  return result.rows.map(normalizeLicense);
}

async function saveLicense(license) {
  await pool.query(
    `insert into licenses (
      license_key, expires_at, revoked, device_id, device_ids,
      max_devices, created_at, last_check_at, last_action, last_app_version
    ) values ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10)
    on conflict (license_key) do update set
      expires_at = excluded.expires_at,
      revoked = excluded.revoked,
      device_id = excluded.device_id,
      device_ids = excluded.device_ids,
      max_devices = excluded.max_devices,
      last_check_at = excluded.last_check_at,
      last_action = excluded.last_action,
      last_app_version = excluded.last_app_version`,
    [
      license.licenseKey,
      Number(license.expiresAt),
      !!license.revoked,
      license.deviceID || "",
      JSON.stringify(Array.isArray(license.deviceIDs) ? license.deviceIDs : []),
      Math.max(1, Number(license.maxDevices || 1)),
      Number(license.createdAt || nowSeconds()),
      Number(license.lastCheckAt || 0),
      license.lastAction || "",
      license.lastAppVersion || ""
    ]
  );
}

async function deleteLicense(key) {
  await pool.query("delete from licenses where license_key = $1", [key]);
}

function checkAdminToken(req, res) {
  const adminToken = req.body.adminToken || req.query.adminToken;
  if (adminToken !== ADMIN_TOKEN) {
    res.status(403).json({ ok: false, message: "Sai admin token" });
    return false;
  }
  return true;
}

async function getAdminLicense(req, res) {
  if (!checkAdminToken(req, res)) return null;

  const key = normalizeKey(req.body.licenseKey);
  if (!key) {
    res.status(400).json({ ok: false, message: "Thiếu licenseKey" });
    return null;
  }

  const license = await getLicense(key);
  if (!license) {
    res.status(404).json({ ok: false, message: "License không tồn tại" });
    return null;
  }

  return { key, license };
}

app.get("/", (req, res) => {
  res.send("PluginLocker license server is running with Supabase/PostgreSQL.");
});

app.get("/healthz", async (req, res) => {
  try {
    await pool.query("select 1");
    res.json({ ok: true, db: true, time: nowSeconds() });
  } catch (error) {
    res.status(500).json({ ok: false, db: false, message: error.message });
  }
});

app.post("/api/license", async (req, res) => {
  try {
    const { licenseKey, deviceID, appVersion, action } = req.body;

    if (!licenseKey || !deviceID) {
      return res.status(400).json({
        valid: false,
        expiresAt: 0,
        message: "Thiếu licenseKey hoặc deviceID"
      });
    }

    const key = normalizeKey(licenseKey);
    const license = await getLicense(key);

    if (!license) {
      return res.json({ valid: false, expiresAt: 0, message: "Giấy phép không tồn tại" });
    }

    if (license.revoked) {
      return res.json({ valid: false, expiresAt: 0, message: "Giấy phép đã bị admin chấm dứt" });
    }

    const now = nowSeconds();
    if (license.expiresAt <= now) {
      return res.json({ valid: false, expiresAt: license.expiresAt, message: "Giấy phép đã hết hạn" });
    }

    if (!license.deviceIDs.includes(deviceID)) {
      if (license.deviceIDs.length >= license.maxDevices) {
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

    await saveLicense(license);

    return res.json({
      valid: true,
      expiresAt: license.expiresAt,
      maxDevices: license.maxDevices,
      usedDevices: license.deviceIDs.length,
      deviceIDs: license.deviceIDs,
      message: "Giấy phép đang hoạt động"
    });
  } catch (error) {
    return res.status(500).json({
      valid: false,
      expiresAt: 0,
      message: "Lỗi server license: " + error.message
    });
  }
});

async function createLicenseHandler(req, res) {
  try {
    const { adminToken, licenseKey, days, maxDevices } = req.body;

    if (adminToken !== ADMIN_TOKEN) {
      return res.status(403).json({ ok: false, message: "Sai admin token" });
    }

    const key = normalizeKey(licenseKey);
    if (!key || !days) {
      return res.status(400).json({ ok: false, message: "Thiếu licenseKey hoặc days" });
    }

    const now = nowSeconds();
    const oldLicense = await getLicense(key);
    const oldDeviceIDs = oldLicense ? oldLicense.deviceIDs : [];
    const max = Math.max(1, Math.floor(Number(maxDevices || oldLicense?.maxDevices || 1)));

    const license = {
      licenseKey: key,
      expiresAt: now + Number(days) * 24 * 60 * 60,
      revoked: false,
      deviceID: oldDeviceIDs[0] || "",
      deviceIDs: oldDeviceIDs,
      maxDevices: max,
      createdAt: oldLicense?.createdAt || now,
      lastCheckAt: oldLicense?.lastCheckAt || 0,
      lastAction: oldLicense ? "extend" : "create",
      lastAppVersion: oldLicense?.lastAppVersion || ""
    };

    await saveLicense(license);

    return res.json({
      ok: true,
      valid: true,
      licenseKey: key,
      expiresAt: license.expiresAt,
      maxDevices: license.maxDevices,
      deviceIDs: license.deviceIDs,
      message: `Đã tạo/gia hạn license ${days} ngày, tối đa ${max} máy`
    });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Lỗi tạo license: " + error.message });
  }
}

app.post("/admin/create", createLicenseHandler);
app.post("/admin/extend", createLicenseHandler);
app.post("/api/admin/create-license", createLicenseHandler);

app.get("/api/admin/licenses", async (req, res) => {
  try {
    if (!checkAdminToken(req, res)) return;
    const licenses = await listLicenses();
    return res.json({ ok: true, licenses });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Lỗi tải license: " + error.message });
  }
});

app.post("/api/admin/reset-device", async (req, res) => {
  try {
    const result = await getAdminLicense(req, res);
    if (!result) return;

    const { license } = result;
    license.deviceID = "";
    license.deviceIDs = [];
    license.lastAction = "reset-device";
    license.lastCheckAt = nowSeconds();

    await saveLicense(license);
    return res.json({ ok: true, message: "Đã reset tất cả máy đang dùng license", license });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Lỗi reset máy: " + error.message });
  }
});

app.post("/api/admin/remove-device", async (req, res) => {
  try {
    const result = await getAdminLicense(req, res);
    if (!result) return;

    const { deviceID } = req.body;
    if (!deviceID) {
      return res.status(400).json({ ok: false, message: "Thiếu deviceID" });
    }

    const { license } = result;
    const beforeCount = license.deviceIDs.length;
    license.deviceIDs = license.deviceIDs.filter(id => id !== deviceID);

    if (license.deviceIDs.length === beforeCount) {
      return res.status(404).json({ ok: false, message: "Không tìm thấy máy này trong license" });
    }

    license.deviceID = license.deviceIDs[0] || "";
    license.lastAction = "remove-device";
    license.lastCheckAt = nowSeconds();

    await saveLicense(license);
    return res.json({ ok: true, message: "Đã tháo 1 máy khỏi license", removedDeviceID: deviceID, license });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Lỗi tháo máy: " + error.message });
  }
});

app.post("/api/admin/revoke", async (req, res) => {
  try {
    const result = await getAdminLicense(req, res);
    if (!result) return;
    const { license } = result;
    license.revoked = true;
    license.lastAction = "revoke";
    license.lastCheckAt = nowSeconds();
    await saveLicense(license);
    return res.json({ ok: true, message: "Đã khóa license", license });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Lỗi khóa license: " + error.message });
  }
});

app.post("/api/admin/unrevoke", async (req, res) => {
  try {
    const result = await getAdminLicense(req, res);
    if (!result) return;
    const { license } = result;
    license.revoked = false;
    license.lastAction = "unrevoke";
    license.lastCheckAt = nowSeconds();
    await saveLicense(license);
    return res.json({ ok: true, message: "Đã mở khóa license", license });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Lỗi mở khóa license: " + error.message });
  }
});

app.post("/api/admin/delete-license", async (req, res) => {
  try {
    const result = await getAdminLicense(req, res);
    if (!result) return;
    await deleteLicense(result.key);
    return res.json({ ok: true, message: "Đã xóa license", licenseKey: result.key });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Lỗi xóa license: " + error.message });
  }
});

app.post("/admin/reset-device", async (req, res) => {
  req.url = "/api/admin/reset-device";
  return app._router.handle(req, res);
});

app.post("/admin/remove-device", async (req, res) => {
  req.url = "/api/admin/remove-device";
  return app._router.handle(req, res);
});

app.post("/admin/revoke", async (req, res) => {
  req.url = "/api/admin/revoke";
  return app._router.handle(req, res);
});

app.post("/admin/unrevoke", async (req, res) => {
  req.url = "/api/admin/unrevoke";
  return app._router.handle(req, res);
});

app.post("/admin/delete-license", async (req, res) => {
  req.url = "/api/admin/delete-license";
  return app._router.handle(req, res);
});

app.post("/admin/list", async (req, res) => {
  try {
    if (!checkAdminToken(req, res)) return;
    const licenses = await listLicenses();
    const licenseObject = {};
    licenses.forEach(item => {
      licenseObject[item.licenseKey] = item;
    });
    return res.json({ ok: true, licenses: licenseObject });
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Lỗi tải license: " + error.message });
  }
});

app.get("/admin", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8" />
  <title>PluginLocker License Admin</title>
  <style>
    body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:#0f1115; color:#f5f5f5; }
    header { padding:22px 28px; border-bottom:1px solid #282c35; background:#151820; }
    main { padding:24px 28px 40px; max-width:1600px; margin:0 auto; }
    .grid { display:grid; grid-template-columns:380px minmax(1000px,1fr); gap:18px; align-items:start; }
    .card { background:#171a22; border:1px solid #2a2f3a; border-radius:14px; padding:16px; }
    label { display:block; font-size:12px; color:#a8b0c0; margin:10px 0 6px; }
    input { width:100%; box-sizing:border-box; border:1px solid #333a48; border-radius:10px; padding:10px 12px; background:#0f1117; color:#fff; }
    button { border:0; border-radius:10px; padding:9px 12px; background:#3b82f6; color:white; cursor:pointer; font-weight:650; }
    button.secondary { background:#374151; }
    button.warning { background:#d97706; }
    button.danger { background:#dc2626; }
    button.green { background:#16a34a; }
    .row { display:flex; gap:8px; align-items:center; }
    .row > * { flex:1; }
    .toolbar { display:flex; gap:10px; align-items:center; justify-content:space-between; margin-bottom:12px; }
    .toolbar input { max-width:360px; }
    table { width:100%; min-width:1180px; border-collapse:separate; border-spacing:0; table-layout:fixed; }
    th,td { padding:14px 10px; border-bottom:1px solid #292f3a; text-align:left; vertical-align:top; font-size:13px; line-height:1.45; overflow-wrap:anywhere; }
    th { color:#a8b0c0; background:#11141b; }
    .pill { display:inline-block; border-radius:999px; padding:3px 8px; font-size:12px; font-weight:700; }
    .ok { background:rgba(22,163,74,.18); color:#4ade80; }
    .bad { background:rgba(220,38,38,.18); color:#f87171; }
    .warn { background:rgba(217,119,6,.18); color:#fbbf24; }
    .muted { color:#8b94a7; font-size:12px; }
    .actions { display:flex; gap:8px; flex-wrap:wrap; min-width:320px; }
    pre { white-space:pre-wrap; word-break:break-word; background:#0f1117; border:1px solid #2a2f3a; border-radius:10px; padding:10px; min-height:40px; max-height:260px; overflow:auto; color:#cbd5e1; }
  </style>
</head>
<body>
  <header><h1>PluginLocker License Admin</h1><div class="muted">Quản lý giấy phép bằng Supabase/PostgreSQL.</div></header>
  <main><div class="grid">
    <section class="card">
      <h2>Tạo / gia hạn license</h2>
      <label>Admin token</label><input id="adminToken" type="password" placeholder="Nhập admin token" autocomplete="off" />
      <label>License key</label><input id="licenseKey" placeholder="PL-USER-30DAYS-001" />
      <div class="row"><div><label>Số ngày</label><input id="days" type="number" min="1" step="1" value="30" /></div><div><label>Số máy tối đa</label><input id="maxDevices" type="number" min="1" step="1" value="1" /></div></div>
      <div class="row" style="margin-top:12px"><button id="createBtn" type="button">Tạo / Gia hạn</button><button id="randomBtn" class="secondary" type="button">Random key</button></div>
      <div class="row" style="margin-top:8px"><button id="saveTokenBtn" class="secondary" type="button">Lưu token</button><button id="reloadBtn" class="secondary" type="button">Tải lại</button></div>
      <h3>Kết quả</h3><pre id="resultBox">Chưa có thao tác.</pre>
    </section>
    <section class="card">
      <div class="toolbar"><h2 style="margin:0">Danh sách license</h2><input id="searchBox" placeholder="Tìm license / device / appVersion" /></div>
      <div class="muted" id="summaryText">Chưa tải dữ liệu.</div>
      <div style="overflow-x:auto; margin-top:12px"><table><thead><tr><th style="width:200px">License</th><th style="width:110px">Trạng thái</th><th style="width:280px">Máy đang dùng</th><th style="width:120px">Số máy</th><th style="width:160px">Thời hạn</th><th style="width:170px">Lần cuối</th><th style="width:320px">Thao tác</th></tr></thead><tbody id="licenseRows"></tbody></table></div>
    </section>
  </div></main>
  <script>
    let licenses = [];
    const $ = (id) => document.getElementById(id);
    function getToken(){ return $("adminToken").value.trim(); }
    function showResult(obj){ $("resultBox").textContent = typeof obj === "string" ? obj : JSON.stringify(obj,null,2); }
    function saveToken(){ localStorage.setItem("pluginlockerAdminToken", getToken()); showResult({ok:true,message:"Đã lưu token trong trình duyệt này."}); }
    function restoreToken(){ $("adminToken").value = localStorage.getItem("pluginlockerAdminToken") || ""; }
    function makeRandomKey(){ const date = new Date().toISOString().slice(0,10).replaceAll("-",""); const rand = Math.random().toString(16).slice(2,10).toUpperCase(); $("licenseKey").value = "PL-" + date + "-" + rand; }
    async function api(path,body){ const res = await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}); const text = await res.text(); let data; try{data=JSON.parse(text)}catch{data={ok:false,message:text}} if(!res.ok) throw data; return data; }
    async function createLicense(){ try{ const data = await api("/api/admin/create-license",{adminToken:getToken(),licenseKey:$("licenseKey").value.trim().toUpperCase(),days:Number($("days").value||30),maxDevices:Number($("maxDevices").value||1)}); showResult(data); await loadLicenses(); }catch(e){ showResult(e); } }
    async function loadLicenses(){ try{ const res = await fetch("/api/admin/licenses?adminToken=" + encodeURIComponent(getToken())); const data = await res.json(); if(!res.ok) throw data; licenses = data.licenses || []; showResult(data); renderTable(); }catch(e){ showResult(e); } }
    async function adminAction(action,licenseKey){ try{ const data = await api("/api/admin/" + action,{adminToken:getToken(),licenseKey}); showResult(data); await loadLicenses(); }catch(e){ showResult(e); } }
    async function removeSelectedDevice(licenseKey,deviceIDs){ if(!Array.isArray(deviceIDs)||deviceIDs.length===0){showResult({ok:false,message:"License này chưa có máy để tháo."});return;} const listText=deviceIDs.map((id,i)=>(i+1)+". "+id).join("\\n"); const input=prompt("Chọn số máy muốn tháo khỏi license:\\n\\n"+listText+"\\n\\nNhập số thứ tự, ví dụ: 1","1"); if(input===null)return; const index=Number(input.trim())-1; if(!Number.isInteger(index)||index<0||index>=deviceIDs.length){showResult({ok:false,message:"Số thứ tự máy không hợp lệ."});return;} const deviceID=deviceIDs[index]; if(!confirm("Tháo máy này khỏi license?\\n\\n"+deviceID))return; try{ const data=await api("/api/admin/remove-device",{adminToken:getToken(),licenseKey,deviceID}); showResult(data); await loadLicenses(); }catch(e){showResult(e);} }
    function formatDate(seconds){ if(!seconds)return "-"; return new Date(seconds*1000).toLocaleString(); }
    function statusFor(item){ const now=Math.floor(Date.now()/1000); if(item.revoked)return '<span class="pill bad">Đã khóa</span>'; if(!item.expiresAt||item.expiresAt<now)return '<span class="pill warn">Hết hạn</span>'; return '<span class="pill ok">Hoạt động</span>'; }
    function remainingText(item){ const now=Math.floor(Date.now()/1000); const seconds=Math.max(0,(item.expiresAt||0)-now); const days=Math.ceil(seconds/86400); if(!seconds)return "Đã hết hạn"; return days>=1?"Còn khoảng "+days+" ngày":"Còn dưới 1 ngày"; }
    function escapeText(value){ return String(value ?? "").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;"); }
    function renderTable(){ const q=$("searchBox").value.trim().toLowerCase(); const filtered=licenses.filter(item=>JSON.stringify(item).toLowerCase().includes(q)); $("summaryText").textContent="Tổng "+licenses.length+" license, đang hiển thị "+filtered.length+"."; $("licenseRows").innerHTML=filtered.map(item=>{ const key=item.licenseKey||""; const revoked=!!item.revoked; const deviceIDs=Array.isArray(item.deviceIDs)?item.deviceIDs:(item.deviceID?[item.deviceID]:[]); const maxDevices=Number(item.maxDevices||1); return '<tr>'+'<td><b>'+escapeText(key)+'</b><div class="muted">created: '+escapeText(formatDate(item.createdAt))+'</div></td>'+'<td>'+statusFor(item)+'</td>'+'<td><div style="white-space:pre-line">'+escapeText(deviceIDs.length?deviceIDs.join("\\n"):"Chưa gắn máy")+'</div><div class="muted">app: '+escapeText(item.lastAppVersion||"-")+'</div></td>'+'<td><b>'+escapeText(deviceIDs.length+"/"+maxDevices)+'</b><div class="muted">đang dùng / tối đa</div></td>'+'<td><div>'+escapeText(remainingText(item))+'</div><div class="muted">'+escapeText(formatDate(item.expiresAt))+'</div></td>'+'<td><div>'+escapeText(formatDate(item.lastCheckAt))+'</div><div class="muted">action: '+escapeText(item.lastAction||"-")+'</div></td>'+'<td class="actions">'+'<button class="secondary" onclick="removeSelectedDevice(\\''+escapeText(key)+'\\', '+escapeText(JSON.stringify(deviceIDs))+')">Tháo 1 máy</button>'+'<button class="secondary" onclick="adminAction(\\'reset-device\\', \\''+escapeText(key)+'\\')">Reset tất cả máy</button>'+'<button class="'+(revoked?"green":"warning")+'" onclick="adminAction(\\''+(revoked?"unrevoke":"revoke")+'\\', \\''+escapeText(key)+'\\')">'+(revoked?"Mở khóa":"Khóa")+'</button>'+'<button class="danger" onclick="confirm(\\'Xóa license '+escapeText(key)+'?\\') && adminAction(\\'delete-license\\', \\''+escapeText(key)+'\\')">Xóa</button>'+'</td>'+'</tr>'; }).join(""); }
    restoreToken();
    $("createBtn").addEventListener("click", createLicense);
    $("randomBtn").addEventListener("click", makeRandomKey);
    $("saveTokenBtn").addEventListener("click", saveToken);
    $("reloadBtn").addEventListener("click", loadLicenses);
    $("searchBox").addEventListener("input", renderTable);
    loadLicenses();
  </script>
</body>
</html>`);
});

ensureSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`PluginLocker license server running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Failed to initialize database schema:", error);
    process.exit(1);
  });
