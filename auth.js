import jwt from "jsonwebtoken";

export function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "No token" });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // { userId, username }
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}