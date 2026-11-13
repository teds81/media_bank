import dotenv from "dotenv"; import bcrypt from "bcryptjs"; import {pool} from "./db.js"; dotenv.config();
const username=process.env.ADMIN_USERNAME||"admin",email=process.env.ADMIN_EMAIL||"admin@mediabank.local",password=process.env.ADMIN_PASSWORD||"Admin@123456";
const hash=await bcrypt.hash(password,12);
await pool.query(`INSERT INTO users(username,email,password_hash,role,is_active) VALUES(?,?,?,'admin',1) ON DUPLICATE KEY UPDATE email=VALUES(email),password_hash=VALUES(password_hash),role='admin',is_active=1`,[username,email,hash]);
console.log(`Admin prêt: ${username}`); await pool.end();
