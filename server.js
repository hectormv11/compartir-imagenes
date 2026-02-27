import express from "express";
import multer from "multer";
import cors from "cors";
import path from "path";
import fs from "fs";
import { pool } from "./db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { requireAuth } from "./auth.js";

const app = express();
app.use(cors());

const UPLOAD_DIR = path.join(process.cwd(), "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

function makeTempPassword() {
  // 12 chars, mezcla segura, fácil de copiar
  return crypto.randomBytes(9).toString("base64url"); // ~12 chars
}

app.use(express.json());

// Crear cuenta: username único, password aleatoria, obliga a cambiarla
app.post("/auth/register", async (req, res) => {
  try {
    const username = (req.body?.username || "").trim();
    if (!username) return res.status(400).json({ error: "username requerido" });
    if (username.length < 3 || username.length > 32) {
      return res.status(400).json({ error: "username debe tener 3-32 caracteres" });
    }
    if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
      return res.status(400).json({ error: "username solo puede tener letras, números, . _ -" });
    }

    const tempPassword = makeTempPassword();
    const password_hash = await bcrypt.hash(tempPassword, 12);

    const q = `
      insert into users (username, password_hash, must_change_password)
      values ($1, $2, true)
      returning id, username, must_change_password
    `;
    const r = await pool.query(q, [username, password_hash]);

    // ✅ Devolvemos la contraseña temporal SOLO en el registro
    res.json({
      user: r.rows[0],
      tempPassword
    });
  } catch (e) {
    // Username duplicado
    if (String(e.code) === "23505") {
      return res.status(409).json({ error: "Ese username ya existe" });
    }
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const username = (req.body?.username || "").trim();
    const password = req.body?.password || "";
    if (!username || !password) return res.status(400).json({ error: "faltan credenciales" });

    const r = await pool.query(
      "select id, username, password_hash, must_change_password from users where username=$1",
      [username]
    );
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: "credenciales incorrectas" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "credenciales incorrectas" });

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: { id: user.id, username: user.username, must_change_password: user.must_change_password }
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.post("/auth/change-password", requireAuth, async (req, res) => {
  try {
    const newPassword = req.body?.newPassword || "";
    if (newPassword.length < 8) return res.status(400).json({ error: "mínimo 8 caracteres" });

    const password_hash = await bcrypt.hash(newPassword, 12);

    await pool.query(
      "update users set password_hash=$1, must_change_password=false where id=$2",
      [password_hash, req.user.userId]
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

const storage = multer.diskStorage({
    destination: (_, __, cb) => cb(null, UPLOAD_DIR),
    filename: (_, file, cb) => {
        const safe = file.originalname.replace(/[^\w.\-]+/g, "_");
        cb(null, `${Date.now()}_${safe}`);
    },
});
const upload = multer({ storage });

app.get("/", (_, res) => {
    res.send("Servidor funcionando correctamente 🚀");
});

app.get("/db-check", async (_, res) => {
    try {
        const r = await pool.query("select now() as now");
        res.json(r.rows[0]);
    } catch (e) {
        res.status(500).json({ error: String(e.message || e) });
    }
});

// ✅ AÑADIR ESTO
app.get("/healthz", (_, res) => res.send("ok"));

app.get("/list", (_, res) => {
    const files = fs.readdirSync(UPLOAD_DIR).slice(-200).reverse();
    res.json(files);
});
// ✅ FIN DE LO AÑADIDO

app.post("/upload", upload.single("image"), (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file" });
    res.json({
        id: req.file.filename,
        originalName: req.file.originalname,
        size: req.file.size,
        url: `/file/${encodeURIComponent(req.file.filename)}`
    });
});

app.get("/file/:id", (req, res) => {
    const filePath = path.join(UPLOAD_DIR, req.params.id);
    if (!fs.existsSync(filePath)) return res.status(404).send("Not found");
    res.sendFile(filePath);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Listening on", PORT));