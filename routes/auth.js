import express from "express";
import argon2 from "argon2";
import jwt from "jsonwebtoken";
import pool from "../config/db.js";

const router = express.Router();

const ACCESS_EXPIRE = "15m";
const REFRESH_EXPIRE = "7d";
const MAX_ATTEMPTS = 5;


// REGISTER (Only first admin)
router.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existing = await pool.query("SELECT * FROM admins LIMIT 1");

    if (existing.rows.length > 0) {
      return res.status(403).json({ message: "Admin already exists" });
    }

    const hashedPassword = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,
      timeCost: 3
    });

    await pool.query(
      "INSERT INTO admins (username, email, password) VALUES ($1,$2,$3)",
      [username, email, hashedPassword]
    );

    res.status(201).json({ message: "Admin created securely" });

  } catch {
    res.status(500).json({ message: "Server error" });
  }
});


// LOGIN
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM admins WHERE email=$1 LIMIT 1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const admin = result.rows[0];

    // Account lock check
    if (admin.locked_until && new Date(admin.locked_until) > new Date()) {
      return res.status(403).json({ message: "Account locked. Try later." });
    }

    const valid = await argon2.verify(admin.password, password);

    if (!valid) {
      const attempts = admin.failed_attempts + 1;

      if (attempts >= MAX_ATTEMPTS) {
        await pool.query(
          "UPDATE admins SET failed_attempts=$1, locked_until=NOW()+INTERVAL '15 minutes' WHERE id=$2",
          [attempts, admin.id]
        );
      } else {
        await pool.query(
          "UPDATE admins SET failed_attempts=$1 WHERE id=$2",
          [attempts, admin.id]
        );
      }

      return res.status(400).json({ message: "Invalid credentials" });
    }

    await pool.query(
      "UPDATE admins SET failed_attempts=0, locked_until=NULL WHERE id=$1",
      [admin.id]
    );

    const accessToken = jwt.sign(
      { id: admin.id },
      process.env.JWT_SECRET,
      { expiresIn: ACCESS_EXPIRE }
    );

    const refreshToken = jwt.sign(
      { id: admin.id },
      process.env.JWT_SECRET,
      { expiresIn: REFRESH_EXPIRE }
    );

    await pool.query(
      "UPDATE admins SET refresh_token=$1 WHERE id=$2",
      [refreshToken, admin.id]
    );

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ accessToken });

  } catch {
    res.status(500).json({ message: "Server error" });
  }
});


// LOGOUT
router.post("/logout", async (req, res) => {
  try {
    const token = req.cookies.refreshToken;

    if (token) {
      const decoded = jwt.decode(token);

      if (decoded) {
        await pool.query(
          "UPDATE admins SET refresh_token=NULL WHERE id=$1",
          [decoded.id]
        );
      }
    }

    res.clearCookie("refreshToken");
    res.json({ message: "Logged out successfully" });

  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

export default router;