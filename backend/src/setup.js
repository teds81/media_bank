import fs from "fs"; import path from "path"; import dotenv from "dotenv"; import mysql from "mysql2/promise"; import {fileURLToPath} from "url"; import bcrypt from "bcryptjs";
dotenv.config(); const __dirname=path.dirname(fileURLToPath(import.meta.url)); const dbName=process.env.DB_NAME||"coach_pronos_media";
const base={host:process.env.DB_HOST||"localhost",port:+(process.env.DB_PORT||3306),user:process.env.DB_USER||"root",password:process.env.DB_PASSWORD||""};
const conn=await mysql.createConnection({...base,multipleStatements:true}); const schema=fs.readFileSync(path.join(__dirname,"../schema.sql"),"utf8"); await conn.query(schema); await conn.end();
const db=mysql.createPool({...base,database:dbName}); const hash=await bcrypt.hash(process.env.ADMIN_PASSWORD||"Admin@123456",12);
await db.query(`INSERT INTO users(username,email,password_hash,role,is_active) VALUES(?,?,?,'admin',1) ON DUPLICATE KEY UPDATE email=VALUES(email),password_hash=VALUES(password_hash),role='admin',is_active=1`,[process.env.ADMIN_USERNAME||"admin",process.env.ADMIN_EMAIL||"admin@mediabank.local",hash]); await db.end(); console.log(`Base ${dbName} et admin configurés.`);
