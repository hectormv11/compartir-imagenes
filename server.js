import express from "express";
import multer from "multer";
import cors from "cors";
import path from "path";
import fs from "fs";
import { pool } from "./db.js";

const app = express();
app.use(cors());

const UPLOAD_DIR = path.join(process.cwd(), "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

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