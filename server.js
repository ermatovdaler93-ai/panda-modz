const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json({limit:"32kb"}));
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "keys.json");

if (!ADMIN_PASSWORD) {
  console.error("Set ADMIN_PASSWORD in your hosting environment.");
  process.exit(1);
}
fs.mkdirSync(DATA_DIR, {recursive:true});
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, "[]");

function readKeys() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, "utf8")); }
  catch { return []; }
}
function writeKeys(rows) {
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(rows, null, 2));
  fs.renameSync(tmp, DB_FILE);
}
function makeKey() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.randomBytes(16);
  let s = [...bytes].map(b => alphabet[b % alphabet.length]).join("");
  return s.match(/.{1,4}/g).join("-");
}
function status(k) {
  if (k.revoked) return "revoked";
  if (k.activatedAt && k.days > 0 && Date.now() > k.activatedAt + k.days*86400000) return "expired";
  return k.activatedAt ? "active" : "free";
}
function admin(req,res,next) {
  const token = req.get("X-Admin-Token") || "";
  if (token !== ADMIN_PASSWORD) return res.status(401).json({message:"Неверный пароль администратора"});
  next();
}
app.get("/api/health", (req,res) => res.json({ok:true}));

app.post("/api/activate", (req,res) => {
  const key = String(req.body.key || "").trim().toUpperCase();
  const device = String(req.body.deviceId || "").trim().slice(0,120);
  if (!/^[A-Z0-9]{4}(?:-[A-Z0-9]{4}){3}$/.test(key)) return res.status(400).json({ok:false,message:"Неверный формат ключа"});
  if (!device) return res.status(400).json({ok:false,message:"Не удалось определить устройство"});
  const rows = readKeys();
  const k = rows.find(x => x.key === key);
  if (!k) return res.status(404).json({ok:false,message:"Ключ не найден"});
  if (k.revoked) return res.status(403).json({ok:false,message:"Ключ отозван"});
  if (status(k) === "expired") return res.status(403).json({ok:false,message:"Срок действия ключа истёк"});
  k.deviceIds = Array.isArray(k.deviceIds) ? k.deviceIds : [];
  if (!k.deviceIds.includes(device) && k.deviceIds.length >= k.devices) {
    return res.status(403).json({ok:false,message:"Превышен лимит устройств"});
  }
  if (!k.activatedAt) k.activatedAt = Date.now();
  if (!k.deviceIds.includes(device)) k.deviceIds.push(device);
  writeKeys(rows);
  return res.json({ok:true,message:"Ключ успешно активирован"});
});

app.get("/api/admin/keys", admin, (req,res) => {
  res.json(readKeys().sort((a,b)=>b.created-a.created));
});
app.post("/api/admin/keys", admin, (req,res) => {
  const count = Math.max(1,Math.min(50,Number(req.body.count)||1));
  const days = Math.max(0,Math.min(3650,Number(req.body.days)||0));
  const devices = Math.max(1,Math.min(99,Number(req.body.devices)||1));
  const note = String(req.body.note||"").slice(0,60);
  const rows = readKeys(), made = [];
  for(let i=0;i<count;i++){
    let key; do { key=makeKey(); } while(rows.some(x=>x.key===key));
    const item={key,days,devices,note,created:Date.now(),activatedAt:null,revoked:false,deviceIds:[]};
    rows.push(item); made.push(item);
  }
  writeKeys(rows);
  res.json({ok:true,keys:made});
});
app.patch("/api/admin/keys/:key", admin, (req,res) => {
  const rows=readKeys(), k=rows.find(x=>x.key===req.params.key);
  if(!k) return res.status(404).json({message:"Ключ не найден"});
  if(typeof req.body.revoked==="boolean") k.revoked=req.body.revoked;
  if(req.body.activate===true && !k.activatedAt) k.activatedAt=Date.now();
  writeKeys(rows); res.json({ok:true});
});
app.delete("/api/admin/keys/:key", admin, (req,res) => {
  const rows=readKeys(), next=rows.filter(x=>x.key!==req.params.key);
  if(next.length===rows.length) return res.status(404).json({message:"Ключ не найден"});
  writeKeys(next); res.json({ok:true});
});
app.get("/admin", (req,res)=>res.sendFile(path.join(__dirname,"public","admin.html")));
app.listen(PORT, ()=>console.log("Panda Modz running on port "+PORT));
