import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import multer from "multer";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import {fileURLToPath} from "url";
import {pool} from "./db.js";
dotenv.config();

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const uploadDir=path.resolve(process.env.UPLOAD_DIR||path.join(__dirname,"../uploads"));
fs.mkdirSync(uploadDir,{recursive:true});
const maxSize=Number(process.env.MAX_FILE_SIZE_GB||20)*1024**3;
const storage=multer.diskStorage({destination:uploadDir,filename:(_req,file,cb)=>cb(null,crypto.randomUUID()+path.extname(file.originalname).toLowerCase())});
const upload=multer({storage,limits:{fileSize:maxSize},fileFilter:(_req,file,cb)=>cb(null,file.mimetype.startsWith("image/")||file.mimetype.startsWith("video/"))});
const app=express();
const frontend=process.env.FRONTEND_URL||"http://localhost:5173";
app.use(cors({origin:frontend,credentials:true}));
app.use(express.json({limit:"2mb"}));
app.use(cookieParser());
const secret=process.env.JWT_SECRET||"dev-only-change-this-secret";
const sign=user=>jwt.sign({id:user.id,username:user.username,role:user.role},secret,{expiresIn:"8h"});
function auth(req,res,next){const token=req.cookies.media_bank_token||((req.headers.authorization||"").startsWith("Bearer ")?req.headers.authorization.slice(7):null);if(!token)return res.status(401).json({error:"Non authentifié"});try{req.user=jwt.verify(token,secret);next()}catch{res.status(401).json({error:"Session expirée"})}}
function admin(req,res,next){if(req.user?.role!=="admin")return res.status(403).json({error:"Accès administrateur requis"});next()}
function typeOf(mime){return mime.startsWith("image/")?"image":"video"}
async function log(userId,action,assetId=null,details=null){try{await pool.query("INSERT INTO activity_logs(user_id,action,asset_id,details) VALUES(?,?,?,?)",[userId,action,assetId,details])}catch{}}
function mapRows(rows){return rows.map(r=>({id:r.id,name:r.name,type:r.type,folder:r.folder||"",summary:r.summary||"",date:new Date(r.created_at).toLocaleDateString("fr-FR"),createdAt:r.created_at,url:`/uploads/${r.stored_name}`,favorite:!!r.favorite,sizeBytes:r.size_bytes}));}

app.get("/api/health",async(_req,res)=>{try{await pool.query("SELECT 1");res.json({ok:true,database:true,uploadDir})}catch(e){res.status(500).json({ok:false,error:e.message})}});
app.post("/api/auth/login",async(req,res)=>{try{const identity=String(req.body.identity||req.body.username||"").trim();const password=String(req.body.password||"");if(!identity||!password)return res.status(400).json({error:"Identifiant et mot de passe requis"});const [rows]=await pool.query("SELECT * FROM users WHERE (username=? OR email=?) AND is_active=1 LIMIT 1",[identity,identity]);const user=rows[0];if(!user||!(await bcrypt.compare(password,user.password_hash)))return res.status(401).json({error:"Identifiant ou mot de passe incorrect"});await pool.query("UPDATE users SET last_login_at=NOW() WHERE id=?",[user.id]);await log(user.id,"LOGIN");res.cookie("media_bank_token",sign(user),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:8*60*60*1000});res.json({user:{id:user.id,username:user.username,email:user.email,role:user.role}})}catch(e){res.status(500).json({error:e.message})}});
app.post("/api/auth/logout",(req,res)=>{res.clearCookie("media_bank_token");res.json({ok:true})});
app.get("/api/auth/me",auth,async(req,res)=>{const [rows]=await pool.query("SELECT id,username,email,role,is_active FROM users WHERE id=? LIMIT 1",[req.user.id]);if(!rows[0]||!rows[0].is_active)return res.status(401).json({error:"Compte inactif"});res.json({user:rows[0]})});

app.use("/uploads",auth,express.static(uploadDir,{maxAge:"1d"}));
app.get("/api/assets",auth,async(req,res)=>{try{const [rows]=await pool.query(`SELECT a.*,f.name folder FROM assets a LEFT JOIN folders f ON f.id=a.folder_id WHERE a.deleted_at IS NULL ORDER BY a.created_at DESC`);res.json(mapRows(rows))}catch(e){res.status(500).json({error:e.message})}});
app.get("/api/trash",auth,async(req,res)=>{try{const [rows]=await pool.query(`SELECT a.*,f.name folder FROM assets a LEFT JOIN folders f ON f.id=a.folder_id WHERE a.deleted_at IS NOT NULL ORDER BY a.deleted_at DESC`);res.json(mapRows(rows))}catch(e){res.status(500).json({error:e.message})}});
app.get("/api/folders",auth,async(_req,res)=>{try{const [rows]=await pool.query(`SELECT f.id,f.name,COUNT(a.id) assetCount FROM folders f LEFT JOIN assets a ON a.folder_id=f.id AND a.deleted_at IS NULL GROUP BY f.id ORDER BY f.name`);res.json(rows)}catch(e){res.status(500).json({error:e.message})}});
app.post("/api/folders",auth,async(req,res)=>{try{const name=String(req.body.name||"").trim();if(!name)return res.status(400).json({error:"Nom requis"});const [r]=await pool.query("INSERT INTO folders(name,created_by) VALUES(?,?)",[name,req.user.id]);await log(req.user.id,"CREATE_FOLDER",null,name);res.status(201).json({id:r.insertId,name})}catch(e){res.status(400).json({error:e.message})}});
app.post("/api/assets/upload",auth,upload.array("files",100),async(req,res)=>{const files=req.files||[];try{if(!files.length)return res.status(400).json({error:"Aucun fichier"});const folder=String(req.body.folder||"").trim();let folderId=null;if(folder){const [fr]=await pool.query("SELECT id FROM folders WHERE name=?",[folder]);if(fr[0])folderId=fr[0].id;else{const [r]=await pool.query("INSERT INTO folders(name,created_by) VALUES(?,?)",[folder,req.user.id]);folderId=r.insertId}}
for(let i=0;i<files.length;i++){const f=files[i];const title=files.length===1&&String(req.body.name||"").trim()?String(req.body.name).trim():path.parse(f.originalname).name;const rawSummaries=req.body.summaries;const summary=Array.isArray(rawSummaries)?String(rawSummaries[i]||""):String(rawSummaries||req.body.summary||"");await pool.query(`INSERT INTO assets(name,type,folder_id,summary,original_name,stored_name,relative_path,mime_type,size_bytes,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)`,[title,typeOf(f.mimetype),folderId,summary,f.originalname,f.filename,path.relative(uploadDir,f.path),f.mimetype,f.size,req.user.id]);}
await log(req.user.id,"UPLOAD",null,`${files.length} fichier(s)`);res.status(201).json({count:files.length})}catch(e){for(const f of files)try{fs.unlinkSync(f.path)}catch{}res.status(500).json({error:e.message})}});
app.patch("/api/assets/:id",auth,async(req,res)=>{try{const id=req.params.id;const fields=[];const vals=[];if(req.body.name!==undefined){const n=String(req.body.name).trim();if(!n)return res.status(400).json({error:"Nom vide"});fields.push("name=?");vals.push(n)}if(req.body.favorite!==undefined){fields.push("favorite=?");vals.push(req.body.favorite?1:0)}if(req.body.folder!==undefined){const [r]=await pool.query("SELECT id FROM folders WHERE name=?",[String(req.body.folder)]);fields.push("folder_id=?");vals.push(r[0]?.id||null)}if(req.body.summary!==undefined){fields.push("summary=?");vals.push(String(req.body.summary))}if(!fields.length)return res.json({ok:true});vals.push(id);await pool.query(`UPDATE assets SET ${fields.join(",")} WHERE id=?`,vals);await log(req.user.id,"UPDATE_ASSET",id);res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}});
app.delete("/api/assets/:id",auth,async(req,res)=>{try{await pool.query("UPDATE assets SET deleted_at=NOW() WHERE id=?",[req.params.id]);await log(req.user.id,"TRASH_ASSET",req.params.id);res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}});
app.post("/api/assets/:id/restore",auth,async(req,res)=>{try{await pool.query("UPDATE assets SET deleted_at=NULL WHERE id=?",[req.params.id]);await log(req.user.id,"RESTORE_ASSET",req.params.id);res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}});
app.delete("/api/assets/:id/permanent",auth,async(req,res)=>{try{const [r]=await pool.query("SELECT stored_name FROM assets WHERE id=?",[req.params.id]);if(r[0])try{fs.unlinkSync(path.join(uploadDir,r[0].stored_name))}catch{}await pool.query("DELETE FROM assets WHERE id=?",[req.params.id]);await log(req.user.id,"DELETE_PERMANENT",req.params.id);res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}});

app.patch("/api/auth/profile",auth,async(req,res)=>{try{const username=String(req.body.username||"").trim();const email=String(req.body.email||"").trim();if(!username||!email)return res.status(400).json({error:"Nom d'utilisateur et email requis"});await pool.query("UPDATE users SET username=?,email=? WHERE id=?",[username,email,req.user.id]);res.json({ok:true,user:{id:req.user.id,username,email,role:req.user.role}})}catch(e){res.status(400).json({error:e.code==="ER_DUP_ENTRY"?"Cet utilisateur ou email existe déjà":e.message})}});
app.post("/api/auth/password",auth,async(req,res)=>{try{const current=String(req.body.currentPassword||"");const next=String(req.body.newPassword||"");if(!current||!next)return res.status(400).json({error:"Mot de passe actuel et nouveau mot de passe requis"});if(next.length<8)return res.status(400).json({error:"Le nouveau mot de passe doit contenir au moins 8 caractères"});const [rows]=await pool.query("SELECT password_hash FROM users WHERE id=? LIMIT 1",[req.user.id]);if(!rows[0]||!(await bcrypt.compare(current,rows[0].password_hash)))return res.status(401).json({error:"Mot de passe actuel incorrect"});await pool.query("UPDATE users SET password_hash=? WHERE id=?",[await bcrypt.hash(next,12),req.user.id]);await log(req.user.id,"CHANGE_PASSWORD");res.json({ok:true})}catch(e){res.status(500).json({error:e.message})}});

app.get("/api/admin/users",auth,admin,async(_req,res)=>{const [rows]=await pool.query("SELECT id,username,email,role,is_active,created_at,last_login_at FROM users ORDER BY created_at DESC");res.json(rows)});
app.get("/api/admin/activity",auth,admin,async(_req,res)=>{const [rows]=await pool.query(`SELECT l.id,l.action,l.details,l.created_at,u.username FROM activity_logs l LEFT JOIN users u ON u.id=l.user_id ORDER BY l.created_at DESC LIMIT 100`);res.json(rows)});
app.post("/api/admin/users",auth,admin,async(req,res)=>{try{const {username,email,password,role="viewer"}=req.body;if(!username||!email||!password)return res.status(400).json({error:"Champs requis"});const hash=await bcrypt.hash(String(password),12);const [r]=await pool.query("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,?)",[username,email,hash,role]);res.status(201).json({id:r.insertId,username,email,role})}catch(e){res.status(400).json({error:e.message})}});
app.patch("/api/admin/users/:id",auth,admin,async(req,res)=>{try{const id=req.params.id;const fields=[];const vals=[];if(req.body.role){fields.push("role=?");vals.push(req.body.role)}if(req.body.is_active!==undefined){fields.push("is_active=?");vals.push(req.body.is_active?1:0)}if(req.body.password){fields.push("password_hash=?");vals.push(await bcrypt.hash(String(req.body.password),12))}if(!fields.length)return res.json({ok:true});vals.push(id);await pool.query(`UPDATE users SET ${fields.join(",")} WHERE id=?`,vals);res.json({ok:true})}catch(e){res.status(400).json({error:e.message})}});

app.use((err,req,res,next)=>{if(err instanceof multer.MulterError)return res.status(400).json({error:`Upload: ${err.message}`});next(err)});
app.listen(process.env.PORT||4000,()=>console.log(`API running on http://localhost:${process.env.PORT||4000}`));
