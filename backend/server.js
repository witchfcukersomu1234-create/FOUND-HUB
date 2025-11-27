require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// DB
const dbFile = path.join(__dirname, 'foundhub.sqlite');
const db = new Database(dbFile);
const initSQL = fs.readFileSync(path.join(__dirname, 'db.sql'), 'utf8');
db.exec(initSQL);

// helpers
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const sign = (u)=> jwt.sign({ id:u.id, email:u.email, role:u.role, name:u.name }, JWT_SECRET, {expiresIn:'7d'});
const auth = (req,res,next)=>{
  const h = req.headers.authorization||''; const t = h.startsWith('Bearer ')?h.slice(7):null;
  if(!t) return res.status(401).json({error:'Missing token'});
  try { req.user = jwt.verify(t, JWT_SECRET); next(); } catch { return res.status(401).json({error:'Invalid token'}); }
};
const ownerOrAdmin = (userId, ownerId, role)=> role==='admin'||userId===ownerId;

// uploads
const storage = multer.diskStorage({
  destination: (req, file, cb)=>{ const d=path.join(__dirname,'uploads'); if(!fs.existsSync(d)) fs.mkdirSync(d); cb(null,d); },
  filename: (req, file, cb)=> cb(null, `item_${Date.now()}${path.extname(file.originalname||'.jpg')}`)
});
const upload = multer({ storage });

// auth
app.post('/api/auth/signup', (req,res)=>{
  const {name,email,password} = req.body; if(!name||!email||!password) return res.status(400).json({error:'All fields required'});
  const hash = bcrypt.hashSync(password,10);
  try{
    const info = db.prepare('INSERT INTO users(name,email,password_hash) VALUES (?,?,?)').run(name,email,hash);
    const user = db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(info.lastInsertRowid);
    return res.json({ user, token: sign(user) });
  }catch(e){ if(String(e.message).includes('UNIQUE')) return res.status(409).json({error:'Email already registered'}); return res.status(500).json({error:'Signup failed'}); }
});
app.post('/api/auth/login', (req,res)=>{
  const {email,password}=req.body; const u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if(!u||!bcrypt.compareSync(password,u.password_hash)) return res.status(401).json({error:'Invalid credentials'});
  const user={id:u.id,name:u.name,email:u.email,role:u.role}; return res.json({ user, token: sign(user) });
});

// items
app.post('/api/items', auth, upload.single('photo'), (req,res)=>{
  const {type,title,description='',category='',location=''}=req.body;
  if(!type||!title) return res.status(400).json({error:'type and title required'});
  const photo_url = req.file ? `/uploads/${req.file.filename}` : null;
  const info = db.prepare(`INSERT INTO items (type,title,description,category,location,photo_url,owner_id) VALUES (?,?,?,?,?,?,?)`)
                 .run(type,title,description,category,location,photo_url,req.user.id);
  res.json(db.prepare('SELECT * FROM items WHERE id=?').get(info.lastInsertRowid));
});
app.get('/api/items', (req,res)=>{
  const {type,q,status='open'}=req.query;
  let sql='SELECT items.*, users.name AS owner_name FROM items JOIN users ON users.id=items.owner_id WHERE 1=1'; const p=[];
  if(type){ sql+=' AND type=?'; p.push(type); }
  if(status){ sql+=' AND status=?'; p.push(status); }
  if(q){ sql+=' AND (title LIKE ? OR description LIKE ? OR location LIKE ? OR category LIKE ?)'; p.push(`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`); }
  sql+=' ORDER BY date_reported DESC'; res.json(db.prepare(sql).all(...p));
});
app.get('/api/items/:id', (req,res)=>{ const it=db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id); if(!it) return res.status(404).json({error:'Not found'}); res.json(it); });
app.patch('/api/items/:id', auth, (req,res)=>{
  const it=db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
  if(!it) return res.status(404).json({error:'Not found'}); if(!ownerOrAdmin(req.user.id,it.owner_id,req.user.role)) return res.status(403).json({error:'Forbidden'});
  const {title,description,category,location,status}=req.body;
  db.prepare(`UPDATE items SET title=COALESCE(?,title),description=COALESCE(?,description),category=COALESCE(?,category),location=COALESCE(?,location),status=COALESCE(?,status) WHERE id=?`)
    .run(title,description,category,location,status,req.params.id);
  res.json(db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id));
});
app.delete('/api/items/:id', auth, (req,res)=>{
  const it=db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
  if(!it) return res.status(404).json({error:'Not found'}); if(!ownerOrAdmin(req.user.id,it.owner_id,req.user.role)) return res.status(403).json({error:'Forbidden'});
  db.prepare('DELETE FROM items WHERE id=?').run(req.params.id); res.json({ok:true});
});

// claims

// Create a claim for an item
app.post('/api/items/:id/claims', auth, (req, res) => {
  const { message } = req.body;

  // find the item being claimed
  const it = db.prepare('SELECT * FROM items WHERE id=?').get(req.params.id);
  if (!it) return res.status(404).json({ error: 'Item not found' });

  // user cannot claim their own post
  if (it.owner_id === req.user.id) {
    return res.status(403).json({ error: 'cannot claim your own post' });
  }

  // insert claim (claimer_id = current user)
  const info = db.prepare(
    'INSERT INTO claims (item_id, claimer_id, message) VALUES (?,?,?)'
  ).run(it.id, req.user.id, message);

  // return the created claim row
  res.json(db.prepare('SELECT * FROM claims WHERE id=?').get(info.lastInsertRowid));
});


// Claims made BY me (as claimer) – your old route (unchanged)
app.get('/api/my/claims', auth, (req, res) => {
  const sql = `
    SELECT c.*, i.title, i.type
    FROM claims c
    JOIN items i ON i.id = c.item_id
    WHERE c.claimer_id = ?
    ORDER BY c.created_at DESC
  `;
  res.json(db.prepare(sql).all(req.user.id));
});


// 🔥 NEW: claims ON my items (as finder / owner)
// use this on the founder's dashboard
app.get('/api/incoming/claims', auth, (req, res) => {
  const sql = `
    SELECT c.*, i.title, i.type, i.location,
           u.name AS claimer_name
    FROM claims c
    JOIN items i ON i.id = c.item_id
    JOIN users u ON u.id = c.claimer_id
    WHERE i.owner_id = ?
    ORDER BY c.created_at DESC
  `;
  res.json(db.prepare(sql).all(req.user.id));
});


// My own items list – your old route (unchanged)
app.get('/api/my/items', auth, (req, res) => {
  res.json(
    db.prepare('SELECT * FROM items WHERE owner_id=? ORDER BY date_reported DESC')
      .all(req.user.id)
  );
});


// Decide on claim (approve / reject) – your old route (unchanged)
app.post('/api/claims/:id/decision', auth, (req, res) => {
  const { decision } = req.body;
  const c = db.prepare('SELECT * FROM claims WHERE id=?').get(req.params.id);
  if (!c) return res.status(404).json({ error: 'Claim not found' });

  const it = db.prepare('SELECT * FROM items WHERE id=?').get(c.item_id);
  if (!it || !ownerOrAdmin(req.user.id, it.owner_id, req.user.role)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  db.prepare('UPDATE claims SET status=? WHERE id=?').run(decision, c.id);

  if (decision === 'approved') {
    db.prepare('UPDATE items SET status="claimed" WHERE id=?').run(it.id);
  }

  res.json(db.prepare('SELECT * FROM claims WHERE id=?').get(c.id));
});


const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Found-Hub API running on port ${PORT}`));

