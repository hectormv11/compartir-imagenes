import path from "path";
import fs from "fs";
import { pool } from "./db.js";

const UPLOAD_DIR = path.join(process.cwd(), "uploads");

async function run() {
  // mensajes expirados
  const r = await pool.query(
    `select object_key
     from messages
     where expires_at <= now()
     limit 500`
  );

  for (const row of r.rows) {
    const filePath = path.join(UPLOAD_DIR, row.object_key);
    try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch {}
  }

  await pool.query(`delete from messages where expires_at <= now()`);
  await pool.query(`delete from share_tokens where expires_at <= now()`);

  console.log(`Deleted ${r.rowCount} expired messages`);
  process.exit(0);
}

run().catch(e => {
  console.error(e);
  process.exit(1);
});