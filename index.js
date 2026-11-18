require("dotenv").config({ quiet: true });
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const crypto = require("crypto");
const { promisify } = require("util");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const scrypt = promisify(crypto.scrypt);

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" })); // photo / file uploads come as base64

// ---- MySQL connection (values come from the .env file) ----
const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || "arinfotek",
  waitForConnections: true,
  connectionLimit: 5,
});

const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret";
const UPLOAD_DIR = path.join(__dirname, "uploads"); // uploaded files are saved here
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

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
  return d ? new Date(d).toLocaleString("en-IN", { timeZone: "Asia/Kolkata", dateStyle: "medium", timeStyle: "short" }) : null;
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

// ---- POST /register : same behaviour as the Flask version ----
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

    await pool.execute(
      `INSERT INTO registrations
        (full_name, email, phone, password_hash, college, register_no, city, address,
         degree, department, degree_status, year_of_study, semester, completion_year,
         course, gender, skills)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        d.full_name, d.email, d.phone, passwordHash, d.college, d.register_no, d.city,
        d.address, d.degree, d.department, d.degree_status,
        d.year_of_study || null, d.semester || null, d.completion_year || null,
        d.course, d.gender, d.skills,
      ]
    );

    return res.status(201).json({ message: "Registered" });
  } catch (e) {
    if (e.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ error: "This email or phone is already registered" });
    }
    console.error("DB error:", e.message);
    return res.status(500).json({ error: "Database error" });
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
    const [rows] = await pool.execute(
      "SELECT id, full_name, password_hash FROM registrations WHERE email = ? OR phone = ? LIMIT 1",
      [username, username]
    );
    const user = rows[0];
    const ok = user ? await verifyPassword(password, user.password_hash) : false;

    // store the login attempt (linked to the registration by foreign key)
    await pool.execute(
      "INSERT INTO login_history (registration_id, username_entered, status) VALUES (?,?,?)",
      [user ? user.id : null, username.slice(0, 100), ok ? "SUCCESS" : "FAILED"]
    );

    if (!ok) {
      return res.status(401).json({ error: "Invalid username or password" });
    }
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    return res.json({ message: "Login successful", name: user.full_name, token });
  } catch (e) {
    console.error("DB error:", e.message);
    return res.status(500).json({ error: "Database error" });
  }
});

// ================= STUDENT PROFILE =================

// GET /profile : registration details + profile + login details + files
app.get("/profile", auth, async (req, res) => {
  try {
    const [regs] = await pool.execute(
      `SELECT id, full_name, email, phone, college, register_no, city, address, degree, department,
              degree_status, year_of_study, semester, completion_year, course, gender, skills, created_at
       FROM registrations WHERE id = ?`, [req.userId]);
    if (!regs.length) return res.status(404).json({ error: "User not found" });

    const [prof] = await pool.execute(
      "SELECT photo, location, current_activity, current_course FROM student_profile WHERE registration_id = ?",
      [req.userId]);
    const [stats] = await pool.execute(
      "SELECT COUNT(*) AS total, MAX(login_time) AS last_login FROM login_history WHERE registration_id = ? AND status = 'SUCCESS'",
      [req.userId]);
    const [recent] = await pool.execute(
      "SELECT status, login_time FROM login_history WHERE registration_id = ? ORDER BY id DESC LIMIT 5",
      [req.userId]);
    const [files] = await pool.execute(
      "SELECT id, file_name, file_size, uploaded_at FROM student_files WHERE registration_id = ? ORDER BY id DESC",
      [req.userId]);

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
      files: files.map((f) => ({ id: f.id, file_name: f.file_name, file_size: f.file_size, uploaded_at: fmt(f.uploaded_at) })),
    });
  } catch (e) {
    console.error("DB error:", e.message);
    return res.status(500).json({ error: "Database error" });
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
    await pool.execute(
      "UPDATE registrations SET full_name=?, phone=?, college=?, city=?, address=?, course=? WHERE id=?",
      [String(d.full_name).trim(), d.phone, String(d.college).trim(), String(d.city).trim(),
       String(d.address).trim(), d.course, req.userId]);

    await pool.execute(
      `INSERT INTO student_profile (registration_id, location, current_activity, current_course)
       VALUES (?,?,?,?)
       ON DUPLICATE KEY UPDATE location = VALUES(location),
         current_activity = VALUES(current_activity), current_course = VALUES(current_course)`,
      [req.userId, String(d.location ?? "").trim() || null,
       String(d.current_activity ?? "").trim() || null, String(d.current_course ?? "").trim() || null]);

    return res.json({ message: "Profile updated" });
  } catch (e) {
    if (e.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "This phone number is already used" });
    console.error("DB error:", e.message);
    return res.status(500).json({ error: "Database error" });
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
    await pool.execute(
      `INSERT INTO student_profile (registration_id, photo) VALUES (?,?)
       ON DUPLICATE KEY UPDATE photo = VALUES(photo)`, [req.userId, image]);
    return res.json({ message: "Photo updated" });
  } catch (e) {
    console.error("DB error:", e.message);
    return res.status(500).json({ error: "Database error" });
  }
});

// POST /profile/files : { file_name, data: "<base64>" }  -> saved in uploads/<id>/
app.post("/profile/files", auth, async (req, res) => {
  const name = String(req.body?.file_name ?? "").trim();
  const buf = Buffer.from(String(req.body?.data ?? ""), "base64");
  const ext = path.extname(name).toLowerCase();

  if (!name || !buf.length) return res.status(400).json({ error: "No file received" });
  if (![".pdf", ".doc", ".docx", ".png", ".jpg", ".jpeg", ".txt"].includes(ext)) {
    return res.status(400).json({ error: "Only PDF, DOC, DOCX, PNG, JPG and TXT files are allowed" });
  }
  if (buf.length > 5 * 1024 * 1024) return res.status(400).json({ error: "File must be under 5 MB" });

  try {
    const safe = name.replace(/[^A-Za-z0-9._-]/g, "_");
    const folder = path.join(UPLOAD_DIR, String(req.userId));
    fs.mkdirSync(folder, { recursive: true });
    const stored = `${Date.now()}_${safe}`;
    fs.writeFileSync(path.join(folder, stored), buf);

    await pool.execute(
      "INSERT INTO student_files (registration_id, file_name, file_path, file_size) VALUES (?,?,?,?)",
      [req.userId, name.slice(0, 150), `uploads/${req.userId}/${stored}`, buf.length]);
    return res.status(201).json({ message: "File uploaded" });
  } catch (e) {
    console.error("Upload error:", e.message);
    return res.status(500).json({ error: "Could not save the file" });
  }
});

// DELETE /profile/files/:id
app.delete("/profile/files/:id", auth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT file_path FROM student_files WHERE id = ? AND registration_id = ?", [req.params.id, req.userId]);
    if (!rows.length) return res.status(404).json({ error: "File not found" });

    fs.rmSync(path.join(__dirname, rows[0].file_path), { force: true });
    await pool.execute("DELETE FROM student_files WHERE id = ?", [req.params.id]);
    return res.json({ message: "File deleted" });
  } catch (e) {
    console.error("DB error:", e.message);
    return res.status(500).json({ error: "Database error" });
  }
});

// ================= ATTENDANCE (calendar + holidays + GPS check) =================
const ACCURACY_LIMIT_M = 30;                          // GPS must be at least this accurate
const BLOCK_MOCK = process.env.BLOCK_MOCK === "true"; // set BLOCK_MOCK=true in .env to reject fake-GPS apps
const pad = (n) => String(n).padStart(2, "0");

// Distance between two GPS points in metres (Haversine formula)
function distanceMeters(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const rad = (x) => (x * Math.PI) / 180;
  const dLat = rad(lat2 - lat1);
  const dLon = rad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(rad(lat1)) * Math.cos(rad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

// Today's date in India time, like 2026-11-17
function todayIST() {
  return new Date().toLocaleDateString("en-CA", { timeZone: "Asia/Kolkata" });
}

// 0 = Sunday ... 6 = Saturday for a "YYYY-MM-DD" date
function weekday(dateStr) {
  return new Date(`${dateStr}T00:00:00Z`).getUTCDay();
}

// Public holiday or Saturday / Sunday?  Returns the reason, or "" for a working day
async function offReason(day) {
  const [h] = await pool.execute("SELECT name FROM public_holidays WHERE holiday_date = ?", [day]);
  if (h.length) return `Today is a public holiday: ${h[0].name}`;
  const dow = weekday(day);
  if (dow === 0) return "Today is Sunday (weekly off)";
  if (dow === 6) return "Today is Saturday (weekly off)";
  return "";
}

// GET /attendance/calendar?year=2026&month=11 : every day of the month with its colour type
app.get("/attendance/calendar", auth, async (req, res) => {
  const today = todayIST();
  const year = Number(req.query.year) || Number(today.slice(0, 4));
  const month = Number(req.query.month) || Number(today.slice(5, 7));
  if (!Number.isInteger(year) || !Number.isInteger(month) || year < 2000 || year > 2100 || month < 1 || month > 12) {
    return res.status(400).json({ error: "Invalid month" });
  }

  try {
    const [crows] = await pool.execute("SELECT company_name, radius_m FROM company_location ORDER BY id LIMIT 1");
    if (!crows.length) return res.status(500).json({ error: "Company location is not set in the database" });

    const [reg] = await pool.execute(
      "SELECT DATE_FORMAT(created_at, '%Y-%m-%d') AS joined FROM registrations WHERE id = ?", [req.userId]);
    const joined = reg[0] ? reg[0].joined : "0000-00-00";

    const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
    const first = `${year}-${pad(month)}-01`;
    const last = `${year}-${pad(month)}-${pad(daysInMonth)}`;

    const [att] = await pool.execute(
      `SELECT DATE_FORMAT(attendance_date, '%Y-%m-%d') AS d, status, check_in_time, distance_m
       FROM attendance WHERE registration_id = ? AND attendance_date BETWEEN ? AND ?`,
      [req.userId, first, last]);
    const [hol] = await pool.execute(
      "SELECT DATE_FORMAT(holiday_date, '%Y-%m-%d') AS d, name FROM public_holidays WHERE holiday_date BETWEEN ? AND ?",
      [first, last]);
    const attMap = new Map(att.map((a) => [a.d, a]));
    const holMap = new Map(hol.map((h) => [h.d, h.name]));

    const days = [];
    const sum = { present: 0, absent: 0, holidays: 0, weekoffs: 0, working_days: 0, percentage: 0 };
    for (let d = 1; d <= daysInMonth; d++) {
      const date = `${year}-${pad(month)}-${pad(d)}`;
      const dow = weekday(date);
      let type;
      let note = "";
      if (attMap.has(date)) {                                  // marked by the student
        const a = attMap.get(date);
        type = a.status;
        note = `${a.status} at ${fmt(a.check_in_time)} (${Math.round(Number(a.distance_m))} m from company)`;
        sum.working_days++;
        if (type === "PRESENT") sum.present++; else sum.absent++;
      } else if (holMap.has(date)) {                           // public holiday
        type = "HOLIDAY"; note = holMap.get(date); sum.holidays++;
      } else if (dow === 0 || dow === 6) {                     // Saturday / Sunday
        type = "WEEKOFF"; note = dow === 0 ? "Sunday - weekly off" : "Saturday - weekly off"; sum.weekoffs++;
      } else if (date < joined) {                              // before the student registered
        type = "NONE";
      } else if (date < today) {                               // working day in the past, not marked
        type = "ABSENT"; note = "Attendance not marked"; sum.absent++; sum.working_days++;
      } else if (date === today) {
        type = "TODAY"; note = "Today - not marked yet";
      } else {
        type = "FUTURE";
      }
      days.push({ date, day: d, type, note });
    }
    sum.percentage = sum.working_days > 0 ? Math.round((sum.present / sum.working_days) * 100) : 0;

    const [trow] = await pool.execute(
      "SELECT status, check_in_time, distance_m FROM attendance WHERE registration_id = ? AND attendance_date = ?",
      [req.userId, today]);
    const t = trow[0];
    const reason = await offReason(today);

    return res.json({
      company: { name: crows[0].company_name, radius_m: crows[0].radius_m },
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
    return res.status(500).json({ error: "Database error" });
  }
});

// GET /holidays?year=2026 : the public holidays table
app.get("/holidays", auth, async (req, res) => {
  const today = todayIST();
  const year = Number(req.query.year) || Number(today.slice(0, 4));
  try {
    const [rows] = await pool.execute(
      `SELECT DATE_FORMAT(holiday_date, '%Y-%m-%d') AS iso, DATE_FORMAT(holiday_date, '%d %b %Y') AS date,
              DAYNAME(holiday_date) AS weekday, name
       FROM public_holidays WHERE YEAR(holiday_date) = ? ORDER BY holiday_date`, [year]);
    return res.json({
      year,
      holidays: rows.map((r) => ({ date: r.date, weekday: r.weekday, name: r.name, past: r.iso < today })),
    });
  } catch (e) {
    console.error("DB error:", e.message);
    return res.status(500).json({ error: "Database error" });
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

    // 1) Public holiday or Saturday / Sunday -> no attendance
    const reason = await offReason(day);
    if (reason) return res.status(400).json({ error: `${reason}. Attendance cannot be marked.` });

    // 2) GPS checks
    if (BLOCK_MOCK && req.body?.mock) {
      return res.status(403).json({ error: "Fake / mock location detected. Attendance not marked." });
    }
    if (acc > ACCURACY_LIMIT_M) {
      return res.status(400).json({ error: `GPS signal is weak (about ${Math.round(acc)} m off). Go to an open area and try again.` });
    }

    const [crows] = await pool.execute("SELECT id, company_name, latitude, longitude, radius_m FROM company_location ORDER BY id LIMIT 1");
    if (!crows.length) return res.status(500).json({ error: "Company location is not set in the database" });
    const c = crows[0];

    const [existing] = await pool.execute(
      "SELECT status FROM attendance WHERE registration_id = ? AND attendance_date = ?", [req.userId, day]);
    if (existing.length && existing[0].status === "PRESENT") {
      return res.json({ status: "PRESENT", message: "You are already marked PRESENT today." });
    }

    // 3) Distance from the company -> PRESENT or ABSENT
    const dist = distanceMeters(lat, lng, Number(c.latitude), Number(c.longitude));
    const status = dist <= c.radius_m ? "PRESENT" : "ABSENT";

    await pool.execute(
      `INSERT INTO attendance (registration_id, company_id, attendance_date, status, latitude, longitude, distance_m, accuracy_m)
       VALUES (?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE status = VALUES(status), check_in_time = CURRENT_TIMESTAMP,
         latitude = VALUES(latitude), longitude = VALUES(longitude),
         distance_m = VALUES(distance_m), accuracy_m = VALUES(accuracy_m)`,
      [req.userId, c.id, day, status, lat, lng, dist.toFixed(1), acc.toFixed(1)]);

    const meters = Math.round(dist);
    return res.json({
      status,
      distance_m: meters,
      radius_m: c.radius_m,
      message: status === "PRESENT"
        ? `Attendance marked PRESENT. You are ${meters} m from ${c.company_name}.`
        : `You are ${meters} m away from ${c.company_name} (allowed: ${c.radius_m} m). Marked ABSENT. Move closer and try again.`,
    });
  } catch (e) {
    console.error("DB error:", e.message);
    return res.status(500).json({ error: "Database error" });
  }
});

// bad JSON etc.
app.use((err, req, res, next) => {
  res.status(400).json({ error: "Invalid request" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on http://127.0.0.1:${PORT}  (keep this window open)`);
});