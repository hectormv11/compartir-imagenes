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

function makeShareToken(len = 8) {
    // token corto, URL-safe
    return crypto.randomBytes(16).toString("base64url").slice(0, len);
}

async function upsertContact(a, b) {
    // guarda contacto en ambas direcciones para que aparezca en lista de los dos
    await pool.query(
        `insert into contacts (user_id, contact_user_id, last_interaction_at)
     values ($1, $2, now())
     on conflict (user_id, contact_user_id)
     do update set last_interaction_at = now()`,
        [a, b]
    );
}

function makeTempPassword() {
    // 12 chars, mezcla segura, fácil de copiar
    return crypto.randomBytes(9).toString("base64url"); // ~12 chars
}

app.get("/users/search", requireAuth, async (req, res) => {
    try {
        const q = (req.query.q || "").trim();
        if (q.length < 1) return res.json([]);

        const r = await pool.query(
            `select id, username
       from users
       where username ilike $1
       order by username asc
       limit 20`,
            [`%${q}%`]
        );

        // no devuelvas al propio usuario
        const out = r.rows.filter(u => u.id !== req.user.userId);
        res.json(out);
    } catch (e) {
        res.status(500).json({ error: String(e.message || e) });
    }
});

app.get("/contacts", requireAuth, async (req, res) => {
    try {
        const r = await pool.query(
            `select u.id, u.username, c.last_interaction_at
       from contacts c
       join users u on u.id = c.contact_user_id
       where c.user_id = $1
       order by c.last_interaction_at desc
       limit 50`,
            [req.user.userId]
        );
        res.json(r.rows);
    } catch (e) {
        res.status(500).json({ error: String(e.message || e) });
    }
});

app.post("/messages/send", requireAuth, upload.single("image"), async (req, res) => {
    try {
        const toUsername = (req.body?.toUsername || "").trim();
        if (!toUsername) return res.status(400).json({ error: "toUsername requerido" });
        if (!req.file) return res.status(400).json({ error: "imagen requerida" });

        // buscar receptor
        const rr = await pool.query("select id, username from users where username=$1", [toUsername]);
        const receiver = rr.rows[0];
        if (!receiver) return res.status(404).json({ error: "receptor no existe" });
        if (receiver.id === req.user.userId) return res.status(400).json({ error: "no puedes enviarte a ti mismo" });

        // 3 horas
        const expiresAt = new Date(Date.now() + 3 * 60 * 60 * 1000);

        // Guardamos en BD (object_key por ahora es el filename)
        const ins = await pool.query(
            `insert into messages (sender_id, receiver_id, object_key, original_name, size_bytes, expires_at)
       values ($1, $2, $3, $4, $5, $6)
       returning id, created_at, expires_at`,
            [req.user.userId, receiver.id, req.file.filename, req.file.originalname, req.file.size, expiresAt]
        );

        // actualizar contactos para ambos
        await upsertContact(req.user.userId, receiver.id);
        await upsertContact(receiver.id, req.user.userId);

        // token corto para “web sin apk” (opcional)
        // Este token lo usaremos para redirigir al login y luego “recibidas”
        let token = null;
        for (let i = 0; i < 5; i++) {
            token = makeShareToken(8);
            const t = await pool.query(
                `insert into share_tokens (token, receiver_id, expires_at)
         values ($1, $2, $3)
         on conflict do nothing
         returning token`,
                [token, receiver.id, expiresAt]
            );
            if (t.rowCount === 1) break;
            token = null;
        }

        res.json({
            ok: true,
            messageId: ins.rows[0].id,
            expiresAt: ins.rows[0].expires_at,
            receiver: receiver.username,
            // link corto: tu frontend luego tendrá /s/:token
            shareLink: token ? `${req.protocol}://${req.get("host")}/s/${token}` : null
        });
    } catch (e) {
        res.status(500).json({ error: String(e.message || e) });
    }
});

app.get("/messages/sent", requireAuth, async (req, res) => {
    try {
        const r = await pool.query(
            `select m.id, u.username as to_username, m.original_name, m.size_bytes, m.created_at, m.expires_at,
              m.object_key
       from messages m
       join users u on u.id = m.receiver_id
       where m.sender_id = $1
         and m.expires_at > now()
       order by m.created_at desc
       limit 100`,
            [req.user.userId]
        );

        // devolvemos url directa al archivo
        const out = r.rows.map(x => ({
            ...x,
            fileUrl: `/file/${encodeURIComponent(x.object_key)}`
        }));

        res.json(out);
    } catch (e) {
        res.status(500).json({ error: String(e.message || e) });
    }
});

app.get("/messages/received", requireAuth, async (req, res) => {
    try {
        const r = await pool.query(
            `select m.id, m.sender_id, su.username as from_username,
              m.original_name, m.size_bytes, m.created_at, m.expires_at, m.object_key
       from messages m
       join users su on su.id = m.sender_id
       where m.receiver_id = $1
         and m.expires_at > now()
       order by su.username asc, m.created_at desc`,
            [req.user.userId]
        );

        // agrupar por from_username
        const grouped = {};
        for (const row of r.rows) {
            if (!grouped[row.from_username]) grouped[row.from_username] = [];
            grouped[row.from_username].push({
                id: row.id,
                original_name: row.original_name,
                size_bytes: row.size_bytes,
                created_at: row.created_at,
                expires_at: row.expires_at,
                fileUrl: `/file/${encodeURIComponent(row.object_key)}`
            });
        }

        res.json(grouped);
    } catch (e) {
        res.status(500).json({ error: String(e.message || e) });
    }
});

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

app.get("/file/:id", requireAuth, async (req, res) => {
    try {
        const key = req.params.id;

        // comprobar que ese archivo pertenece a un mensaje válido para este usuario
        const r = await pool.query(
            `select id
       from messages
       where object_key = $1
         and expires_at > now()
         and (sender_id = $2 or receiver_id = $2)
       limit 1`,
            [key, req.user.userId]
        );

        if (r.rowCount === 0) return res.status(403).send("Forbidden");

        const filePath = path.join(UPLOAD_DIR, key);
        if (!fs.existsSync(filePath)) return res.status(404).send("Not found");

        res.sendFile(filePath);
    } catch (e) {
        res.status(500).send("Error");
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Listening on", PORT));