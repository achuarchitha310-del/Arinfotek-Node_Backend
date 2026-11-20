require("dotenv").config({ quiet: true });
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");
const { promisify } = require("util");
const jwt = require("jsonwebtoken");
const path = require("path");
const { put, del } = require("@vercel/blob");

const scrypt = promisify(crypto.scrypt);

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" })); // photo / file uploads come as base64

// ---- Clean DATABASE_URL just in case it has quotes or psql prefix ----
const rawDbUrl = (process.env.DATABASE_URL || "")
  .trim()
  .replace(/^psql\s+['"]?|['"]$/g, "");

// ---- Neon PostgreSQL connection (DATABASE_URL from Vercel / .env) ----
const pool = new Pool({
  connectionString: rawDbUrl,
  ssl: { rejectUnauthorized: false },
});

const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret";

// Health check route for browser testing
app.get("/", (req, res) => {
  res.json({
    status: "OK",
    message: "AR Infotek Backend is running on Vercel + Neon!",
    db_configured: Boolean(rawDbUrl),
  });
});

// Checks the login token sent by the app
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  try {
    req.userId = jwt.verify(token, JWT_SECRET).id;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Please login again" });
  }
}

// Date -> "16 Nov 2026, 5:30 pm" (India time)
function fmt(d) {
  return d
    ? new Date(d).toLocaleString("en-IN", {
        timeZone: "Asia/Kolkata",
        dateStyle: "medium",
        timeStyle: "short",
      })
    : null;
}

// Hash the password (never store the real password)
async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const key = await scrypt(password, salt, 64);
  return `scrypt$${salt}$${key.toString("hex")}`;
}

// Check a typed password against the stored hash
async function verifyPassword(password, stored) {
  const [scheme, salt, hex] = String(stored).split("$");
  if (scheme !== "scrypt" || !salt || !hex) return false;
  const key = await scrypt(password, salt, 64);
  const expected = Buffer.from(hex, "hex");
  return key.length === expected.length && crypto.timingSafeEqual(key, expected);
}

const REQUIRED = [
  "full_name", "email", "phone", "password", "college", "register_no", "city",
  "address", "degree", "department", "degree_status", "course", "gender", "skills",
];

// ---- POST /register ----
app.post("/register", async (req, res) => {
  const d = req.body || {};

  for (const k of REQUIRED) {
    if (!String(d[k] ?? "").trim()) {
      return res.status(400).json({ error: `${k} is required` });
    }
  }
  if (!/^\S+@\S+\.\S+$/.test(d.email)) {
    return res.status(400).json({ error: "Invalid email" });
  }
  if (!/^[6-9]\d{9}$/.test(d.phone)) {
    return res.status(400).json({ error: "Invalid phone number" });
  }

  try {
    const passwordHash = await hashPassword(String(d.password));

    await pool.query(
      `INSERT INTO registrations
        (full_name, email, phone, password_hash, college, register_no, city, address,
         degree, department, degree_status, year_of_study, semester, completion_year,
         course, gender, skills)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
      [
        d.full_name, d.email, d.phone, passwordHash, d.college, d.register_no, d.city,
        d.address, d.degree, d.department, d.degree_status,
        d.year_of_study || null, d.semester || null, d.completion_year || null,
        d.course, d.gender, d.skills,
      ]
    );

    return res.status(201).json({ message: "Registered" });
  } catch (e) {
    if (e.code === "23505") {
      return res.status(409).json({ error: "This email or phone is already registered" });
    }
    console.error("DB error:", e.message);
    return res.status(500).json({ error: e.message || "Database error" });
  }
});

// ---- POST /login : username = email or phone ----
app.post("/login", async (req, res) => {
  const username = String(req.body?.username ?? "").trim();
  const password = String(req.body?.password ?? "");

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }

  try {
    const { rows } = await pool.query(
      "SELECT id, full_name, password_hash FROM registrations WHERE email = $1 OR phone = $2 LIMIT 1",
      [username, username]
    );
    const user = rows[0];
    const ok = user ? await verifyPassword(password, user.password_hash) : false;

    // store the login attempt
    await pool.query(
      "INSERT INTO login_history (registration_id, username_entered, status) VALUES ($1,$2,$3)",
      [user ? user.id : null, username.slice(0, 100), ok ? "SUCCESS" : "FAILED"]
    );

    if (!ok) {
      return res.status(401).json({ error: "Invalid username or password" });
    }
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    return res.json({ message: "Login successful", name: user.full_name, token });
  } catch (e) {
    console.error("DB error:", e.message);
    return res.status(500).json({ error: e.message || "Database error" });
  }
});

// ================= PASSWORD RESET (EMAIL OTP VIA RESEND) =================

// ---- POST /forgot-password : { email } ----
app.post("/forgot-password", async (req, res) => {
  const email = String(req.body?.email ?? "").trim().toLowerCase();
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: "Please enter a valid registered email" });
  }
  if (!process.env.RESEND_API_KEY) {
    return res.status(500).json({ error: "Email service (RESEND_API_KEY) is not configured" });
  }

  try {
    const { rows } = await pool.query(
      "SELECT id, full_name, email FROM registrations WHERE LOWER(email) = $1 LIMIT 1",
      [email]
    );
    if (!rows.length) {
      return res.status(404).json({ error: "This email is not registered" });
    }

    const user = rows[0];
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const expires = new Date(Date.now() + 10 * 60 * 1000); // valid for 10 minutes

    await pool.query(
      "UPDATE registrations SET reset_otp = $1, reset_otp_expires = $2 WHERE id = $3",
      [otp, expires, user.id]
    );

    const mailRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: "AR INFOTEK <onboarding@resend.dev>",
        to: [user.email],
        subject: "AR INFOTEK - Password Reset OTP",
        html: `
          <div style="font-family:Arial,sans-serif;padding:20px;max-width:480px;margin:auto;border:1px solid #e2e8f0;border-radius:12px;">
            <h2 style="color:#1E5AA8;margin-bottom:8px;">AR INFOTEK</h2>
            <p>Hello <b>${user.full_name}</b>,</p>
            <p>Use the 6-digit OTP below to reset your password:</p>
            <div style="background:#f1f5f9;padding:14px;text-align:center;border-radius:8px;font-size:28px;font-weight:bold;letter-spacing:6px;color:#0f172a;margin:16px 0;">
              ${otp}
            </div>
            <p style="color:#64748b;font-size:13px;">This OTP expires in 10 minutes. If you didn't request a password reset, ignore this email.</p>
          </div>
        `,
      }),
    });

    const mailData = await mailRes.json().catch(() => ({}));
    if (!mailRes.ok) {
      console.error("Resend error:", mailData);
      return res.status(500).json({
        error: mailData.message || "Failed to send OTP email",
      });
    }

    return res.json({ message: `OTP sent to ${user.email}` });
  } catch (e) {
    console.error("Forgot password error:", e.message);
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// ---- POST /reset-password : { email, otp, new_password } ----
app.post("/reset-password", async (req, res) => {
  const email = String(req.body?.email ?? "").trim().toLowerCase();
  const otp = String(req.body?.otp ?? "").trim();
  const newPassword = String(req.body?.new_password ?? "");

  if (!email || !otp || !newPassword) {
    return res.status(400).json({ error: "Email, OTP, and new password are required" });
  }
  if (newPassword.length < 4) {
    return res.status(400).json({ error: "New password must be at least 4 characters" });
  }

  try {
    const { rows } = await pool.query(
      "SELECT id, reset_otp, reset_otp_expires FROM registrations WHERE LOWER(email) = $1 LIMIT 1",
      [email]
    );
    if (!rows.length) {
      return res.status(404).json({ error: "Email not found" });
    }

    const user = rows[0];
    if (!user.reset_otp || user.reset_otp !== otp) {
      return res.status(400).json({ error: "Invalid OTP" });
    }
    if (!user.reset_otp_expires || new Date() > new Date(user.reset_otp_expires)) {
      return res.status(400).json({ error: "OTP expired. Please request a new OTP" });
    }

    const newHash = await hashPassword(newPassword);
    await pool.query(
      "UPDATE registrations SET password_hash = $1, reset_otp = NULL, reset_otp_expires = NULL WHERE id = $2",
      [newHash, user.id]
    );

    return res.json({ message: "Password updated successfully! Please login." });
  } catch (e) {
    console.error("Reset password error:", e.message);
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// ================= STUDENT PROFILE =================

// GET /profile
app.get("/profile", auth, async (req, res) => {
  try {
    const { rows: regs } = await pool.query(
      `SELECT id, full_name, email, phone, college, register_no, city, address, degree, department,
              degree_status, year_of_study, semester, completion_year, course, gender, skills, created_at
       FROM registrations WHERE id = $1`,
      [req.userId]
    );
    if (!regs.length) return res.status(404).json({ error: "User not found" });

    const { rows: prof } = await pool.query(
      "SELECT photo, location, current_activity, current_course FROM student_profile WHERE registration_id = $1",
      [req.userId]
    );
    const { rows: stats } = await pool.query(
      "SELECT COUNT(*) AS total, MAX(login_time) AS last_login FROM login_history WHERE registration_id = $1 AND status = 'SUCCESS'",
      [req.userId]
    );
    const { rows: recent } = await pool.query(
      "SELECT status, login_time FROM login_history WHERE registration_id = $1 ORDER BY id DESC LIMIT 5",
      [req.userId]
    );
    const { rows: files } = await pool.query(
      "SELECT id, file_name, file_path, file_size, uploaded_at FROM student_files WHERE registration_id = $1 ORDER BY id DESC",
      [req.userId]
    );

    const reg = regs[0];
    reg.created_at = fmt(reg.created_at);

    return res.json({
      registration: reg,
      profile: prof[0] || {},
      logins: {
        total: Number(stats[0].total),
        last: fmt(stats[0].last_login),
        recent: recent.map((r) => ({ status: r.status, login_time: fmt(r.login_time) })),
      },
      files: files.map((f) => ({
        id: f.id,
        file_name: f.file_name,
        file_url: f.file_path,
        file_size: f.file_size,
        uploaded_at: fmt(f.uploaded_at),
      })),
    });
  } catch (e) {
    console.error("DB error:", e.message);
    return res.status(500).json({ error: e.message || "Database error" });
  }
});

// PUT /profile : edit details
app.put("/profile", auth, async (req, res) => {
  const d = req.body || {};
  for (const k of ["full_name", "phone", "college", "city", "address", "course"]) {
    if (!String(d[k] ?? "").trim()) return res.status(400).json({ error: `${k} is required` });
  }
  if (!/^[A-Za-z ]{3,}$/.test(String(d.full_name).trim())) {
    return res.status(400).json({ error: "Name must be at least 3 letters (letters and spaces only)" });
  }
  if (!/^[6-9]\d{9}$/.test(String(d.phone))) {
    return res.status(400).json({ error: "Invalid phone number" });
  }

  try {
    await pool.query(
      "UPDATE registrations SET full_name=$1, phone=$2, college=$3, city=$4, address=$5, course=$6 WHERE id=$7",
      [
        String(d.full_name).trim(),
        d.phone,
        String(d.college).trim(),
        String(d.city).trim(),
        String(d.address).trim(),
        d.course,
        req.userId,
      ]
    );

    await pool.query(
      `INSERT INTO student_profile (registration_id, location, current_activity, current_course)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (registration_id) DO UPDATE SET
         location = EXCLUDED.location,
         current_activity = EXCLUDED.current_activity,
         current_course = EXCLUDED.current_course`,
      [
        req.userId,
        String(d.location ?? "").trim() || null,
        String(d.current_activity ?? "").trim() || null,
        String(d.current_course ?? "").trim() || null,
      ]
    );

    return res.json({ message: "Profile updated" });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "This phone number is already used" });
    console.error("DB error:", e.message);
    return res.status(500).json({ error: e.message || "Database error" });
  }
});

// POST /profile/photo : { image: "<base64 jpeg>" }
app.post("/profile/photo", auth, async (req, res) => {
  const image = String(req.body?.image ?? "");
  const buf = Buffer.from(image, "base64");
  if (image.length > 700000 || buf.length < 100 || buf[0] !== 0xff || buf[1] !== 0xd8) {
    return res.status(400).json({ error: "Please choose a valid photo (JPEG, small size)" });
  }
  try {
    await pool.query(
      `INSERT INTO student_profile (registration_id, photo) VALUES ($1,$2)
       ON CONFLICT (registration_id) DO UPDATE SET photo = EXCLUDED.photo`,
      [req.userId, image]
    );
    return res.json({ message: "Photo updated" });
  } catch (e) {
    console.error("DB error:", e.message);
    return res.status(500).json({ error: e.message || "Database error" });
  }
});

// POST /profile/files : { file_name, data: "<base64>" } -> Stored in Vercel Blob (Max 200 KB)
app.post("/profile/files", auth, async (req, res) => {
  const name = String(req.body?.file_name ?? "").trim();
  const buf = Buffer.from(String(req.body?.data ?? ""), "base64");
  const ext = path.extname(name).toLowerCase();

  if (!name || !buf.length) {
    return res.status(400).json({ error: "No file received" });
  }
  if (![".pdf", ".doc", ".docx", ".png", ".jpg", ".jpeg", ".txt"].includes(ext)) {
    return res.status(400).json({ error: "Only PDF, DOC, DOCX, PNG, JPG and TXT files are allowed" });
  }
  if (buf.length > 200 * 1024) {
    return res.status(400).json({ error: "File size must be under 200 KB" });
  }

  try {
    const safe = name.replace(/[^A-Za-z0-9._-]/g, "_");
    const blobPath = `students/${req.userId}/${Date.now()}_${safe}`;

    const blob = await put(blobPath, buf, {
      access: "public",
    });

    await pool.query(
      "INSERT INTO student_files (registration_id, file_name, file_path, file_size) VALUES ($1,$2,$3,$4)",
      [req.userId, name.slice(0, 150), blob.url, buf.length]
    );

    return res.status(201).json({ message: "File uploaded", url: blob.url });
  } catch (e) {
    console.error("Blob upload error:", e.message);
    return res.status(500).json({ error: e.message || "Could not upload the file" });
  }
});

// DELETE /profile/files/:id -> Deletes from Vercel Blob + Neon DB
app.delete("/profile/files/:id", auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT file_path FROM student_files WHERE id = $1 AND registration_id = $2",
      [req.params.id, req.userId]
    );
    if (!rows.length) return res.status(404).json({ error: "File not found" });

    if (rows[0].file_path && rows[0].file_path.startsWith("http")) {
      await del(rows[0].file_path);
    }

    await pool.query("DELETE FROM student_files WHERE id = $1", [req.params.id]);
    return res.json({ message: "File deleted" });
  } catch (e) {
    console.error("Blob delete error:", e.message);
    return res.status(500).json({ error: e.message || "Database error" });
  }
});

// ================= ATTENDANCE (calendar + holidays + GPS check) =================
const ACCURACY_LIMIT_M = 30;
const BLOCK_MOCK = process.env.BLOCK_MOCK === "true";
const pad = (n) => String(n).padStart(2, "0");

function distanceMeters(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const rad = (x) => (x * Math.PI) / 180;
  const dLat = rad(lat2 - lat1);
  const dLon = rad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(rad(lat1)) * Math.cos(rad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

function todayIST() {
  return new Date().toLocaleDateString("en-CA", { timeZone: "Asia/Kolkata" });
}

function weekday(dateStr) {
  return new Date(`${dateStr}T00:00:00Z`).getUTCDay();
}

async function offReason(day) {
  const { rows: h } = await pool.query(
    "SELECT name FROM public_holidays WHERE holiday_date = $1",
    [day]
  );
  if (h.length) return `Today is a public holiday: ${h[0].name}`;
  const dow = weekday(day);
  if (dow === 0) return "Today is Sunday (weekly off)";
  if (dow === 6) return "Today is Saturday (weekly off)";
  return "";
}

// GET /attendance/calendar?year=2026&month=11
app.get("/attendance/calendar", auth, async (req, res) => {
  const today = todayIST();
  const year = Number(req.query.year) || Number(today.slice(0, 4));
  const month = Number(req.query.month) || Number(today.slice(5, 7));
  if (
    !Number.isInteger(year) ||
    !Number.isInteger(month) ||
    year < 2000 ||
    year > 2100 ||
    month < 1 ||
    month > 12
  ) {
    return res.status(400).json({ error: "Invalid month" });
  }

  try {
    const { rows: crows } = await pool.query(
      "SELECT company_name, radius_m FROM company_location ORDER BY id LIMIT 1"
    );
    if (!crows.length)
      return res.status(500).json({ error: "Company location is not set in the database" });

    const { rows: reg } = await pool.query(
      "SELECT TO_CHAR(created_at, 'YYYY-MM-DD') AS joined FROM registrations WHERE id = $1",
      [req.userId]
    );
    const joined = reg[0] ? reg[0].joined : "0000-00-00";

    const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
    const first = `${year}-${pad(month)}-01`;
    const last = `${year}-${pad(month)}-${pad(daysInMonth)}`;

    const { rows: att } = await pool.query(
      `SELECT TO_CHAR(attendance_date, 'YYYY-MM-DD') AS d, status, check_in_time, distance_m
       FROM attendance WHERE registration_id = $1 AND attendance_date BETWEEN $2 AND $3`,
      [req.userId, first, last]
    );
    const { rows: hol } = await pool.query(
      "SELECT TO_CHAR(holiday_date, 'YYYY-MM-DD') AS d, name FROM public_holidays WHERE holiday_date BETWEEN $1 AND $2",
      [first, last]
    );
    const attMap = new Map(att.map((a) => [a.d, a]));
    const holMap = new Map(hol.map((h) => [h.d, h.name]));

    const days = [];
    const sum = { present: 0, absent: 0, holidays: 0, weekoffs: 0, working_days: 0, percentage: 0 };
    for (let d = 1; d <= daysInMonth; d++) {
      const date = `${year}-${pad(month)}-${pad(d)}`;
      const dow = weekday(date);
      let type;
      let note = "";
      if (attMap.has(date)) {
        const a = attMap.get(date);
        type = a.status;
        note = `${a.status} at ${fmt(a.check_in_time)} (${Math.round(Number(a.distance_m))} m from company)`;
        sum.working_days++;
        if (type === "PRESENT") sum.present++;
        else sum.absent++;
      } else if (holMap.has(date)) {
        type = "HOLIDAY";
        note = holMap.get(date);
        sum.holidays++;
      } else if (dow === 0 || dow === 6) {
        type = "WEEKOFF";
        note = dow === 0 ? "Sunday - weekly off" : "Saturday - weekly off";
        sum.weekoffs++;
      } else if (date < joined) {
        type = "NONE";
      } else if (date < today) {
        type = "ABSENT";
        note = "Attendance not marked";
        sum.absent++;
        sum.working_days++;
      } else if (date === today) {
        type = "TODAY";
        note = "Today - not marked yet";
      } else {
        type = "FUTURE";
      }
      days.push({ date, day: d, type, note });
    }
    sum.percentage = sum.working_days > 0 ? Math.round((sum.present / sum.working_days) * 100) : 0;

    const { rows: trow } = await pool.query(
      "SELECT status, check_in_time, distance_m FROM attendance WHERE registration_id = $1 AND attendance_date = $2",
      [req.userId, today]
    );
    const t = trow[0];
    const reason = await offReason(today);

    return res.json({
      company: { name: crows[0].company_name, radius_m: Number(crows[0].radius_m) || 30 },
      today: {
        date: today,
        status: t ? t.status : null,
        time: t ? fmt(t.check_in_time) : null,
        distance_m: t ? Number(t.distance_m) : null,
        can_mark: !reason && !(t && t.status === "PRESENT"),
        reason,
      },
      month: { year, month },
      days,
      summary: sum,
    });
  } catch (e) {
    console.error("DB error:", e.message);
    return res.status(500).json({ error: e.message || "Database error" });
  }
});

// GET /holidays?year=2026
app.get("/holidays", auth, async (req, res) => {
  const today = todayIST();
  const year = Number(req.query.year) || Number(today.slice(0, 4));
  try {
    const { rows } = await pool.query(
      `SELECT TO_CHAR(holiday_date, 'YYYY-MM-DD') AS iso,
              TO_CHAR(holiday_date, 'DD Mon YYYY') AS date,
              TRIM(TO_CHAR(holiday_date, 'Day')) AS weekday,
              name
       FROM public_holidays
       WHERE EXTRACT(YEAR FROM holiday_date) = $1
       ORDER BY holiday_date`,
      [year]
    );
    return res.json({
      year,
      holidays: rows.map((r) => ({
        date: r.date,
        weekday: r.weekday,
        name: r.name,
        past: r.iso < today,
      })),
    });
  } catch (e) {
    console.error("DB error:", e.message);
    return res.status(500).json({ error: e.message || "Database error" });
  }
});

// POST /attendance/mark : { latitude, longitude, accuracy, mock }
app.post("/attendance/mark", auth, async (req, res) => {
  const lat = Number(req.body?.latitude);
  const lng = Number(req.body?.longitude);
  const acc = Number(req.body?.accuracy ?? 0) || 0;

  if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180) {
    return res.status(400).json({ error: "Invalid location received" });
  }

  try {
    const day = todayIST();

    const reason = await offReason(day);
    if (reason) return res.status(400).json({ error: `${reason}. Attendance cannot be marked.` });

    if (BLOCK_MOCK && req.body?.mock) {
      return res.status(403).json({ error: "Fake / mock location detected. Attendance not marked." });
    }
    if (acc > ACCURACY_LIMIT_M) {
      return res.status(400).json({
        error: `GPS signal is weak (about ${Math.round(acc)} m off). Go to an open area and try again.`,
      });
    }

    const { rows: crows } = await pool.query(
      "SELECT id, company_name, latitude, longitude, radius_m FROM company_location ORDER BY id LIMIT 1"
    );
    if (!crows.length)
      return res.status(500).json({ error: "Company location is not set in the database" });
    const c = crows[0];

    const { rows: existing } = await pool.query(
      "SELECT status FROM attendance WHERE registration_id = $1 AND attendance_date = $2",
      [req.userId, day]
    );
    if (existing.length && existing[0].status === "PRESENT") {
      return res.json({ status: "PRESENT", message: "You are already marked PRESENT today." });
    }

    const companyLat = Number(c.latitude) || 12.75432717;
    const companyLng = Number(c.longitude) || 77.82871361;
    const allowedRadius = Number(c.radius_m) || 30;

    const dist = distanceMeters(lat, lng, companyLat, companyLng);
    const meters = Math.round(dist);
    const status = dist <= allowedRadius ? "PRESENT" : "ABSENT";

    await pool.query(
      `INSERT INTO attendance (registration_id, company_id, attendance_date, status, latitude, longitude, distance_m, accuracy_m)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (registration_id, attendance_date) DO UPDATE SET
         status = EXCLUDED.status,
         check_in_time = CURRENT_TIMESTAMP,
         latitude = EXCLUDED.latitude,
         longitude = EXCLUDED.longitude,
         distance_m = EXCLUDED.distance_m,
         accuracy_m = EXCLUDED.accuracy_m`,
      [req.userId, c.id, day, status, lat, lng, dist.toFixed(1), acc.toFixed(1)]
    );

    return res.json({
      success: status === "PRESENT",
      status,
      distance_m: meters,
      radius_m: allowedRadius,
      message:
        status === "PRESENT"
          ? `Attendance marked PRESENT. You are ${meters} m from ${c.company_name}.`
          : `Attendance marked ABSENT. You are ${meters} m away from ${c.company_name} (allowed: ${allowedRadius} m).`,
    });
  } catch (e) {
    console.error("DB error:", e.message);
    return res.status(500).json({ error: e.message || "Database error" });
  }
});

// bad JSON etc.
app.use((err, req, res, next) => {
  res.status(400).json({ error: "Invalid request" });
});

if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://127.0.0.1:${PORT}`);
  });
}

module.exports = app;