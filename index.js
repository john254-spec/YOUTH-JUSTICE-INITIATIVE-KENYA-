require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = Number(process.env.PORT || 10000);
const PRODUCTION = process.env.NODE_ENV === "production";

if (PRODUCTION) {
if (!process.env.SESSION_SECRET ||
process.env.SESSION_SECRET.length < 32) {
throw new Error(
"Set SESSION_SECRET to a random value of at least 32 characters."
);
}

if (!process.env.BASE_URL ||
!process.env.BASE_URL.startsWith("https://")) {
throw new Error("Set BASE_URL to your public HTTPS Render URL.");
}

if (!process.env.DATA_DIR) {
throw new Error(
"Set DATA_DIR to the mount path of your Render persistent disk."
);
}
}

const DATA_DIR = path.resolve(
process.env.DATA_DIR || path.join(__dirname, "data")
);

fs.mkdirSync(DATA_DIR, {
recursive: true,
mode: 0o700
});

app.disable("x-powered-by");

if (PRODUCTION) {
app.set("trust proxy", 1);
}

app.use(helmet({
contentSecurityPolicy: {
directives: {
defaultSrc: ["'self'"],
scriptSrc: ["'self'", "'unsafe-inline'"],
styleSrc: ["'self'", "'unsafe-inline'"],
imgSrc: ["'self'", "data:", "https:"],
formAction: ["'self'"],
objectSrc: ["'none'"],
baseUri: ["'self'"],
frameAncestors: ["'none'"]
}
}
}));

app.use(express.urlencoded({
extended: false,
limit: "20kb"
}));

app.use(express.json({
limit: "20kb"
}));

app.use(rateLimit({
windowMs: 15 * 60 * 1000,
limit: 200,
standardHeaders: "draft-8",
legacyHeaders: false
}));

// --------------------------------------------------
// SQLITE DATABASE
// --------------------------------------------------

const db = new sqlite3.Database(
path.join(DATA_DIR, "yjik.sqlite")
);

db.configure("busyTimeout", 10000);

db.run("PRAGMA foreign_keys = ON");

function run(sql, params = []) {
return new Promise((resolve, reject) => {
db.run(sql, params, function (err) {
if (err) return reject(err);

  resolve({
    id: this.lastID,
    changes: this.changes
  });
});

});
}

function get(sql, params = []) {
return new Promise((resolve, reject) => {
db.get(sql, params, (err, row) => {
if (err) return reject(err);

  resolve(row);
});

});
}

function all(sql, params = []) {
return new Promise((resolve, reject) => {
db.all(sql, params, (err, rows) => {
if (err) return reject(err);

  resolve(rows);
});

});
}

async function initialiseDatabase() {
await run("CREATE TABLE IF NOT EXISTS users ( id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP )");

await run("CREATE TABLE IF NOT EXISTS password_resets ( id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE )");

await run("CREATE TABLE IF NOT EXISTS contact_messages ( id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP )");

await run("CREATE TABLE IF NOT EXISTS donations ( id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL, amount INTEGER NOT NULL, programme TEXT NOT NULL, message TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'pledged', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP )");

console.log("SQLite database ready.");
}

// --------------------------------------------------
// EMAIL CONFIGURATION
// --------------------------------------------------

let mailer = null;

if (
process.env.SMTP_HOST &&
process.env.SMTP_USER &&
process.env.SMTP_PASS
) {
mailer = nodemailer.createTransport({
host: process.env.SMTP_HOST,
port: Number(process.env.SMTP_PORT || 587),
secure: process.env.SMTP_SECURE === "true",
auth: {
user: process.env.SMTP_USER,
pass: process.env.SMTP_PASS
}
});
}

async function sendEmail(options) {
if (!mailer) {
console.warn("SMTP is not configured; email was not sent.");
return false;
}

await mailer.sendMail({
from: process.env.MAIL_FROM || process.env.SMTP_USER,
...options
});

return true;
}

// --------------------------------------------------
// SESSIONS
// --------------------------------------------------

app.use(session({
name: "yjik.sid",

secret: PRODUCTION
? process.env.SESSION_SECRET
: (process.env.SESSION_SECRET || "local-development-secret-change-me"),

store: new SQLiteStore({
db: "sessions.sqlite",
dir: DATA_DIR
}),

resave: false,
saveUninitialized: false,

cookie: {
httpOnly: true,
secure: PRODUCTION,
sameSite: "lax",
maxAge: 8 * 60 * 60 * 1000
}
}));

// --------------------------------------------------
// HELPERS
// --------------------------------------------------

function escapeHTML(value = "") {
return String(value).replace(/[&<>"']/g, ch => ({
"&": "&",
"<": "<",
">": ">",
'"': """,
"'": "'"
})[ch]);
}

function emailNormal(value = "") {
return String(value).trim().toLowerCase();
}

function validEmail(value) {
return /^[^\s@]+@[^\s@]+.[^\s@]+$/.test(value);
}

function validPassword(value) {
return typeof value === "string" &&
value.length >= 12 &&
Buffer.byteLength(value, "utf8") <= 72;
}

function flashRedirect(res, pathName, message) {
res.redirect(
pathName + "?message=" + encodeURIComponent(message)
);
}

function requireLogin(req, res, next) {
if (!req.session.user) {
return flashRedirect(
res,
"/login",
"Please log in to access your dashboard."
);
}

next();
}

function regenerateSession(req) {
return new Promise((resolve, reject) => {
req.session.regenerate(err => err ? reject(err) : resolve());
});
}

function saveSession(req) {
return new Promise((resolve, reject) => {
req.session.save(err => err ? reject(err) : resolve());
});
}

function destroySession(req) {
return new Promise((resolve, reject) => {
req.session.destroy(err => err ? reject(err) : resolve());
});
}

function publicURL(req, route) {
const base = process.env.BASE_URL ||
"${req.protocol}://${req.get("host")}";

return new URL(route, base).toString();
}

const authLimiter = rateLimit({
windowMs: 15 * 60 * 1000,
limit: 10,
standardHeaders: "draft-8",
legacyHeaders: false
});

const formLimiter = rateLimit({
windowMs: 15 * 60 * 1000,
limit: 8,
standardHeaders: "draft-8",
legacyHeaders: false
});

// --------------------------------------------------
// INLINE HTML, CSS AND JAVASCRIPT
// --------------------------------------------------

function renderPage(title, content, req) {
const user = req.session.user;

const nav = user
? "<a href="/dashboard">Dashboard</a> <a href="/logout">Logout</a>"
: "<a href="/login">Login</a> <a class="nav-join" href="/signup">Join Us</a>";

const notice = req.query.message
? "<div class="notice">${escapeHTML(req.query.message)}</div>"
: "";

return `<!DOCTYPE html>

<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#105a38">
<meta name="description" content="Youth Justice Initiative Kenya promotes youth rights, access to justice, legal awareness, community safety and youth empowerment.">
<title>${escapeHTML(title)} | Youth Justice Initiative Kenya</title><style>
:root {
  --green: #105a38;
  --dark: #083b25;
  --deep: #052d1b;
  --lime: #c8f169;
  --mint: #eaf7ee;
  --pale: #f5faf6;
  --white: #ffffff;
  --text: #21362a;
  --muted: #66786c;
  --border: #dce9df;
  --shadow: 0 12px 36px rgba(8,59,37,.09);
}

* { box-sizing: border-box; }

html { scroll-behavior: smooth; }

body {
  margin: 0;
  color: var(--text);
  background: var(--pale);
  font-family: Arial, Helvetica, sans-serif;
  line-height: 1.7;
}

a { color: var(--green); }

button, input, textarea, select { font: inherit; }

button { cursor: pointer; }

.topbar {
  background: var(--deep);
  color: white;
  text-align: center;
  padding: 8px 16px;
  font-size: 12px;
}

.navbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding: 15px 5%;
  background: white;
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 20;
}

.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  text-decoration: none;
  color: var(--dark);
}

.brand-icon {
  display: grid;
  place-items: center;
  width: 46px;
  height: 46px;
  border-radius: 13px;
  background: var(--green);
  color: var(--lime);
  font-weight: 900;
}

.brand strong {
  display: block;
  font-size: 14px;
  line-height: 1.4;
}

.brand small {
  display: block;
  font-size: 11px;
  color: var(--muted);
}

.nav-links {
  display: flex;
  align-items: center;
  gap: 19px;
}

.nav-links a {
  color: var(--text);
  font-size: 13px;
  font-weight: 700;
  text-decoration: none;
}

.nav-links a:hover { color: var(--green); }

.nav-join {
  padding: 10px 16px;
  border-radius: 8px;
  background: var(--green);
  color: white !important;
}

.menu-toggle {
  display: none;
  background: var(--green);
  color: white;
  border: 0;
  padding: 9px 12px;
  border-radius: 7px;
}

.button {
  display: inline-block;
  padding: 12px 19px;
  border-radius: 8px;
  border: 0;
  background: var(--green);
  color: white;
  text-decoration: none;
  font-weight: 700;
}

.button:hover { background: var(--dark); }

.button.lime {
  background: var(--lime);
  color: var(--deep);
}

.button.light {
  background: white;
  color: var(--green);
}

.hero {
  background:
    radial-gradient(circle at 85% 15%, rgba(200,241,105,.18), transparent 32%),
    linear-gradient(135deg, #083b25, #167347);
  color: white;
  padding: 88px 7%;
}

.hero-inner {
  max-width: 1200px;
  margin: auto;
  display: grid;
  grid-template-columns: 1.35fr .8fr;
  gap: 48px;
  align-items: center;
}

.eyebrow {
  color: var(--lime);
  font-weight: 800;
  letter-spacing: 2px;
  font-size: 12px;
  text-transform: uppercase;
}

.hero h1 {
  font-size: clamp(36px, 5vw, 62px);
  line-height: 1.12;
  letter-spacing: -1.5px;
  margin: 18px 0;
}

.hero p {
  max-width: 680px;
  color: #e0eee5;
  font-size: 17px;
}

.hero-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 28px;
}

.hero-box {
  padding: 28px;
  border-radius: 18px;
  background: rgba(255,255,255,.09);
  border: 1px solid rgba(255,255,255,.16);
}

.hero-box h3 { color: var(--lime); }

.hero-box li { margin: 10px 0; }

.section { padding: 72px 7%; }

.section.white { background: white; }

.section-heading {
  max-width: 780px;
  margin: 0 auto 38px;
  text-align: center;
}

.section-heading h2 {
  color: var(--dark);
  font-size: clamp(28px, 4vw, 42px);
  line-height: 1.2;
  margin: 12px 0;
}

.section-heading p { color: var(--muted); }

.grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 22px;
  max-width: 1200px;
  margin: auto;
}

.grid.two {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.card {
  background: white;
  padding: 25px;
  border: 1px solid var(--border);
  border-radius: 14px;
  box-shadow: var(--shadow);
}

.card h3 { color: var(--green); }

.card p { color: var(--muted); }

.icon { font-size: 30px; }

.green-section {
  background: var(--green);
  color: white;
}

.green-section .section-heading h2 { color: white; }

.green-section .section-heading p { color: #dcece2; }

.green-section .card {
  background: rgba(255,255,255,.08);
  border-color: rgba(255,255,255,.16);
  box-shadow: none;
}

.green-section .card h3 { color: var(--lime); }

.green-section .card p { color: #e2eee6; }

.page-header {
  padding: 55px 7%;
  text-align: center;
  color: white;
  background: linear-gradient(130deg, var(--deep), var(--green));
}

.page-header h1 {
  font-size: clamp(32px, 5vw, 46px);
  margin: 0 0 10px;
}

.page-header p {
  max-width: 760px;
  margin: auto;
  color: #e0eee5;
}

.content {
  max-width: 1000px;
  margin: auto;
}

.content h2 { color: var(--green); }

.form-wrap {
  max-width: 560px;
  margin: 40px auto;
  padding: 30px;
  background: white;
  border: 1px solid var(--border);
  border-radius: 16px;
  box-shadow: var(--shadow);
}

.form-wrap h1, .form-wrap h2 { color: var(--green); }

.form-wrap > p { color: var(--muted); }

.field { margin: 16px 0; }

label {
  display: block;
  font-size: 14px;
  font-weight: 700;
  margin-bottom: 7px;
}

input, textarea, select {
  width: 100%;
  padding: 12px;
  border: 1px solid #cbdccf;
  border-radius: 8px;
  background: white;
  color: var(--text);
}

input:focus, textarea:focus, select:focus {
  outline: 2px solid #72bc8d;
  border-color: var(--green);
}

input[type=checkbox] { width: auto; }

textarea { min-height: 125px; resize: vertical; }

.full { width: 100%; }

.help { color: var(--muted); font-size: 12px; }

.notice {
  max-width: 900px;
  margin: 16px auto;
  padding: 13px 18px;
  background: var(--mint);
  border: 1px solid #b6dfc3;
  color: var(--dark);
  border-radius: 9px;
  text-align: center;
}

.dashboard-shell {
  min-height: 600px;
  background: #eaf5ed;
  padding: 35px 5%;
}

.dashboard {
  max-width: 1250px;
  margin: auto;
  display: grid;
  grid-template-columns: 250px 1fr;
  gap: 24px;
}

.sidebar {
  background: var(--dark);
  color: white;
  padding: 24px 17px;
  border-radius: 17px;
  align-self: start;
  box-shadow: var(--shadow);
}

.sidebar h3 {
  color: var(--lime);
  padding: 0 10px;
}

.sidebar a {
  display: block;
  color: white;
  text-decoration: none;
  padding: 11px 12px;
  border-radius: 8px;
  margin: 5px 0;
}

.sidebar a:hover, .sidebar a.active {
  background: #176c43;
}

.dash-main { min-width: 0; }

.dash-heading {
  background: linear-gradient(120deg, #105a38, #218453);
  color: white;
  padding: 27px;
  border-radius: 16px;
  box-shadow: var(--shadow);
}

.dash-heading h1 { margin: 0; }

.dash-heading p { color: #e1f0e5; }

.stat-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 17px;
  margin: 20px 0;
}

.stat-card {
  background: white;
  border: 1px solid var(--border);
  border-left: 5px solid var(--green);
  padding: 20px;
  border-radius: 12px;
}

.stat-card strong {
  display: block;
  font-size: 25px;
  color: var(--green);
}

.stat-card span {
  color: var(--muted);
  font-size: 13px;
}

.dash-panel {
  padding: 25px;
  background: white;
  border: 1px solid var(--border);
  border-radius: 14px;
  margin-bottom: 20px;
}

.dash-panel h2 { color: var(--green); }

.action-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 15px;
}

.action-card {
  background: #f3faf4;
  border: 1px solid var(--border);
  padding: 19px;
  border-radius: 12px;
}

.action-card h3 { color: var(--green); }

.action-card a {
  font-weight: 700;
  text-decoration: none;
}

.cta {
  text-align: center;
  background: #e2f3e6;
}

.cta h2 { color: var(--dark); }

.footer {
  background: var(--deep);
  color: #dce9df;
  padding: 50px 7% 20px;
}

.footer-grid {
  max-width: 1200px;
  margin: auto;
  display: grid;
  grid-template-columns: 2fr 1fr 1fr;
  gap: 30px;
}

.footer h3, .footer h4 { color: var(--lime); }

.footer a {
  display: block;
  margin: 8px 0;
  color: #e1ece4;
  text-decoration: none;
  font-size: 14px;
}

.copyright {
  max-width: 1200px;
  margin: 30px auto 0;
  padding-top: 18px;
  border-top: 1px solid rgba(255,255,255,.15);
  color: #b8cdbd;
  font-size: 12px;
}

@media (max-width: 950px) {
  .menu-toggle { display: block; }

  .navbar { flex-wrap: wrap; }

  .nav-links {
    display: none;
    width: 100%;
    flex-direction: column;
    align-items: stretch;
    gap: 10px;
    padding: 10px 0;
  }

  .nav-links.open { display: flex; }

  .nav-links a { padding: 7px 0; }

  .hero-inner { grid-template-columns: 1fr; }

  .dashboard { grid-template-columns: 1fr; }

  .sidebar { display: grid; grid-template-columns: repeat(2, 1fr); }

  .sidebar h3 { grid-column: 1 / -1; }

  .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

@media (max-width: 600px) {
  .hero { padding: 55px 6%; }

  .section { padding: 50px 6%; }

  .grid, .grid.two, .footer-grid,
  .stat-grid, .action-grid {
    grid-template-columns: 1fr;
  }

  .form-wrap { margin: 24px 5%; padding: 22px; }

  .dashboard-shell { padding: 20px 4%; }

  .sidebar { grid-template-columns: 1fr; }

  .brand strong { font-size: 12px; }
}
</style></head><body>
<div class="topbar">
  Advancing youth rights, justice, dignity and opportunity in Kenya.
</div><nav class="navbar">
  <a class="brand" href="/">
    <span class="brand-icon">YJ</span>
    <span>
      <strong>Youth Justice Initiative Kenya</strong>
      <small>Justice • Dignity • Opportunity</small>
    </span>
  </a><button
id="menuToggle"
class="menu-toggle"
type="button"
aria-expanded="false"
aria-controls="navLinks"

«Menu ☰</button>»

  <div class="nav-links" id="navLinks">
    <a href="/">Home</a>
    <a href="/about">About Us</a>
    <a href="/programmes">Programmes</a>
    <a href="/contact">Contact</a>
    <a href="/donate">Donate</a>
    ${nav}
  </div>
</nav>${notice}

<main>${content}</main><footer class="footer">
  <div class="footer-grid">
    <div>
      <h3>Youth Justice Initiative Kenya</h3>  <p>
    Promoting youth rights awareness, access to justice,
    legal awareness, community safety and youth empowerment.
  </p>

  <p>
    Community presence: Lurende Market, Khatiri,
    Bungoma County, Kenya.
  </p>

  <p>
    Our programme descriptions represent intended areas of work.
    Actual activities depend on available resources and capacity.
  </p>
</div>

<div>
  <h4>Explore</h4>
  <a href="/about">About Us</a>
  <a href="/programmes">Our Programmes</a>
  <a href="/contact">Contact Us</a>
  <a href="/privacy">Privacy</a>
</div>

<div>
  <h4>Get Involved</h4>
  <a href="/signup">Join Our Community</a>
  <a href="/donate">Support Our Work</a>
  <a href="/login">Member Login</a>
</div>

  </div>  <div class="copyright">
    © ${new Date().getFullYear()} Youth Justice Initiative Kenya.
    All rights reserved.
    <br>
    This website is not a substitute for professional legal advice
    or emergency services.
  </div>
</footer><script>
  const menuButton = document.getElementById("menuToggle");
  const nav = document.getElementById("navLinks");

  menuButton.addEventListener("click", () => {
    const open = nav.classList.toggle("open");
    menuButton.setAttribute("aria-expanded", String(open));
  });

  document.querySelectorAll("form[data-validate]").forEach(form => {
    form.addEventListener("submit", event => {
      if (!form.checkValidity()) {
        event.preventDefault();
        form.reportValidity();
      }
    });
  });

  const password = document.getElementById("password");
  const confirmPassword = document.getElementById("confirmPassword");

  if (password && confirmPassword) {
    confirmPassword.addEventListener("input", () => {
      confirmPassword.setCustomValidity(
        confirmPassword.value === password.value
          ? ""
          : "Passwords do not match."
      );
    });

    password.addEventListener("input", () => {
      confirmPassword.setCustomValidity(
        !confirmPassword.value ||
        confirmPassword.value === password.value
          ? ""
          : "Passwords do not match."
      );
    });
  }
</script></body>
</html>`;
}function pageHeader(title, description) {
return "<section class="page-header"> <h1>${escapeHTML(title)}</h1> <p>${escapeHTML(description)}</p> </section>";
}

function formPage(title, description, fields, buttonText, action) {
return `
<section class="form-wrap">
<h1>${escapeHTML(title)}</h1>
<p>${escapeHTML(description)}</p>

  <form method="POST" action="${action}" data-validate>
    ${fields}

    <button class="button full" type="submit">
      ${escapeHTML(buttonText)}
    </button>
  </form>
</section>

`;
}

function sendPage(res, title, content, req, status = 200) {
res.status(status).send(renderPage(title, content, req));
}

// --------------------------------------------------
// HOME
// --------------------------------------------------

app.get("/", (req, res) => {
const content = `
<section class="hero">
<div class="hero-inner">
<div>
<span class="eyebrow">
Rights • Justice • Empowerment
</span>

      <h1>
        Empowering Young People.
        Advancing Justice.
        Building Safer Communities.
      </h1>

      <p>
        Youth Justice Initiative Kenya is a community-oriented
        initiative focused on youth rights awareness, access to
        justice, legal awareness, community safety and opportunities
        that help young people participate meaningfully in society.
      </p>

      <div class="hero-actions">
        <a class="button lime" href="/about">Discover Our Mission</a>
        <a class="button light" href="/signup">Join Our Community</a>
      </div>
    </div>

    <div class="hero-box">
      <h3>Our Commitment</h3>
      <ul>
        <li>Promoting youth rights and responsibilities.</li>
        <li>Encouraging fairness and accountability.</li>
        <li>Sharing information about opportunities.</li>
        <li>Supporting peaceful, safer communities.</li>
        <li>Strengthening youth participation.</li>
      </ul>
    </div>
  </div>
</section>

<section class="section">
  <div class="section-heading">
    <span class="eyebrow">Our Focus</span>
    <h2>Justice, dignity and opportunity for every young person</h2>

    <p>
      We aim to bridge information gaps and encourage young people
      to understand their rights, find appropriate support and
      participate in positive community development.
    </p>
  </div>

  <div class="grid">
    <article class="card">
      <div class="icon">⚖️</div>
      <h3>Youth Rights</h3>
      <p>
        Promote awareness of constitutional rights, equality,
        responsibilities and fair treatment.
      </p>
    </article>

    <article class="card">
      <div class="icon">🤝</div>
      <h3>Access to Justice</h3>
      <p>
        Help young people understand complaint channels and
        identify appropriate legal or public support services.
      </p>
    </article>

    <article class="card">
      <div class="icon">🌱</div>
      <h3>Youth Empowerment</h3>
      <p>
        Share information about employment, education, training
        and entrepreneurship opportunities.
      </p>
    </article>
  </div>
</section>

<section class="section white">
  <div class="section-heading">
    <span class="eyebrow">What We Aim to Do</span>
    <h2>Turning awareness into positive community action</h2>
  </div>

  <div class="grid two">
    <article class="card">
      <h3>Legal Awareness</h3>
      <p>
        Encourage informed discussions about rights, responsibilities,
        legal procedures and available assistance.
      </p>
    </article>

    <article class="card">
      <h3>Community Safety</h3>
      <p>
        Promote peaceful conflict resolution, violence prevention
        awareness and constructive community engagement.
      </p>
    </article>

    <article class="card">
      <h3>Partnerships</h3>
      <p>
        Explore cooperation with civil society organisations,
        humanitarian actors, educators and relevant institutions.
      </p>
    </article>

    <article class="card">
      <h3>Youth Participation</h3>
      <p>
        Encourage youth voices in public participation, leadership
        and community decision-making.
      </p>
    </article>
  </div>
</section>

<section class="section green-section">
  <div class="section-heading">
    <span class="eyebrow">Our Values</span>
    <h2>Principles that guide our work</h2>
  </div>

  <div class="grid">
    <article class="card">
      <h3>Integrity</h3>
      <p>Honesty, accountability and responsible leadership.</p>
    </article>

    <article class="card">
      <h3>Human Dignity</h3>
      <p>Respect, fairness and non-discrimination.</p>
    </article>

    <article class="card">
      <h3>Inclusion</h3>
      <p>Meaningful participation and respect for diverse voices.</p>
    </article>
  </div>
</section>

<section class="section cta">
  <h2>Be part of positive change</h2>
  <p>
    Whether you are a young person, volunteer, professional,
    organisation or potential donor, we welcome enquiries about
    working together towards our shared objectives.
  </p>
  <a class="button" href="/contact">Contact Us</a>
  <a class="button" href="/donate">Support Our Work</a>
</section>

`;

sendPage(res, "Home", content, req);
});

// --------------------------------------------------
// ABOUT
// --------------------------------------------------

app.get("/about", (req, res) => {
const content = `
${pageHeader(
"About Us",
"Our mission, vision, objectives and commitment to young people."
)}

<section class="section">
  <div class="content">
    <h2>Who We Are</h2>

    <p>
      Youth Justice Initiative Kenya is a youth-focused initiative
      concerned with human rights awareness, access to justice,
      legal awareness, community safety and youth empowerment.
    </p>

    <p>
      With a community presence in Lurende Market, Khatiri,
      Bungoma County, Kenya, the initiative seeks to encourage
      informed, peaceful and constructive participation by young
      people in matters affecting their lives and communities.
    </p>

    <h2>Our Mission</h2>

    <p>
      To promote youth rights, access to justice, legal awareness
      and empowerment through community education, partnerships,
      advocacy and responsible engagement.
    </p>

    <h2>Our Vision</h2>

    <p>
      A just, inclusive and peaceful society where young people
      understand their rights, access appropriate support and
      participate meaningfully in community development.
    </p>

    <h2>Our Objectives</h2>

    <ul>
      <li>Promote awareness of constitutional rights and freedoms.</li>
      <li>Improve understanding of appropriate justice mechanisms.</li>
      <li>Encourage access to reliable legal information.</li>
      <li>Share information about education and employment opportunities.</li>
      <li>Promote peaceful coexistence and conflict prevention.</li>
      <li>Encourage youth participation in public decision-making.</li>
      <li>Build partnerships that strengthen youth development.</li>
    </ul>

    <h2>Our Principles</h2>

    <p>
      Our approach is guided by integrity, human dignity,
      accountability, inclusion, non-discrimination, peaceful
      engagement and respect for the law.
    </p>

    <h2>Our Community</h2>

    <p>
      Our community presence is in Lurende Market, Khatiri,
      Bungoma County. Programme delivery and expansion depend
      on organisational capacity, resources and partnerships.
    </p>

    <p>
      Programme descriptions on this website identify intended
      areas of work. They do not imply that every programme is
      currently funded or operating.
    </p>
  </div>
</section>

`;

sendPage(res, "About Us", content, req);
});

// --------------------------------------------------
// PROGRAMMES
// --------------------------------------------------

app.get("/programmes", (req, res) => {
const programmes = [
[
"Youth Rights Awareness",
"Educational activities about constitutional rights, equality, freedom of expression, non-discrimination and responsible citizenship."
],
[
"Access to Justice",
"Information about appropriate complaint channels, legal aid resources and referrals to qualified service providers."
],
[
"Community Safety",
"Awareness of peaceful conflict resolution, violence prevention, responsible citizenship and community wellbeing."
],
[
"Youth Empowerment",
"Sharing information about employment, scholarships, education, entrepreneurship and training opportunities."
],
[
"Youth Participation",
"Encouraging young people to contribute to public participation, leadership, community dialogue and policy discussions."
],
[
"Partnerships",
"Exploring collaboration with civil society organisations, humanitarian actors, educators, legal professionals and public institutions."
]
];

const cards = programmes.map(item => "<article class="card"> <h3>${escapeHTML(item[0])}</h3> <p>${escapeHTML(item[1])}</p> </article>").join("");

sendPage(
res,
"Our Programmes",
`
${pageHeader(
"Our Programmes",
"Our intended programme areas in youth rights, justice and empowerment."
)}

  <section class="section">
    <div class="grid">${cards}</div>
  </section>

  <section class="section cta">
    <h2>Interested in collaboration?</h2>
    <p>
      Contact us to discuss potential programme partnerships,
      volunteering or support for community activities.
    </p>
    <a class="button" href="/contact">Discuss a Partnership</a>
  </section>
`,
req

);
});

// --------------------------------------------------
// SIGN UP
// --------------------------------------------------

app.get("/signup", (req, res) => {
const fields = `
<div class="field">
<label for="name">Full name</label>
<input id="name" name="name" minlength="2"
maxlength="100" autocomplete="name" required>
</div>

<div class="field">
  <label for="email">Email address</label>
  <input id="email" name="email" type="email"
    maxlength="254" autocomplete="email" required>
</div>

<div class="field">
  <label for="password">Password</label>
  <input id="password" name="password" type="password"
    minlength="12" maxlength="72"
    autocomplete="new-password" required>
  <p class="help">Use at least 12 characters.</p>
</div>

<div class="field">
  <label for="confirmPassword">Confirm password</label>
  <input id="confirmPassword" name="confirmPassword"
    type="password" minlength="12" maxlength="72"
    autocomplete="new-password" required>
</div>

<div class="field">
  <label>
    <input type="checkbox" name="agree" value="yes" required>
    I have read the <a href="/privacy">privacy information</a>.
  </label>
</div>

`;

sendPage(
res,
"Sign Up",
formPage(
"Create Your Account",
"Join the Youth Justice Initiative Kenya online community.",
fields,
"Create Account",
"/signup"
),
req
);
});

app.post("/signup", authLimiter, async (req, res, next) => {
try {
const name = String(req.body.name || "").trim();
const email = emailNormal(req.body.email);
const password = req.body.password;

if (name.length < 2 || name.length > 100 ||
    !validEmail(email) ||
    !validPassword(password) ||
    password !== req.body.confirmPassword ||
    req.body.agree !== "yes") {
  return flashRedirect(
    res,
    "/signup",
    "Check your details, password and privacy acknowledgement."
  );
}

const existing = await get(
  "SELECT id FROM users WHERE email = ?",
  [email]
);

if (existing) {
  return flashRedirect(
    res,
    "/signup",
    "An account could not be created with those details."
  );
}

const passwordHash = await bcrypt.hash(password, 12);

const result = await run(
  "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
  [name, email, passwordHash]
);

await regenerateSession(req);

req.session.user = {
  id: result.id,
  name,
  email
};

await saveSession(req);

res.redirect("/dashboard");

} catch (error) {
if (error.code === "SQLITE_CONSTRAINT") {
return flashRedirect(
res,
"/signup",
"Unable to create the account. Please try again."
);
}

next(error);

}
});

// --------------------------------------------------
// LOGIN
// --------------------------------------------------

app.get("/login", (req, res) => {
const fields = `
<div class="field">
<label for="email">Email address</label>
<input id="email" name="email" type="email"
maxlength="254" autocomplete="username" required>
</div>

<div class="field">
  <label for="password">Password</label>
  <input id="password" name="password" type="password"
    maxlength="72" autocomplete="current-password" required>
</div>

<p><a href="/forgot-password">Forgot your password?</a></p>
<p>New user? <a href="/signup">Create an account</a>.</p>

`;

sendPage(
res,
"Login",
formPage(
"Welcome Back",
"Log in to your YJIK account.",
fields,
"Login",
"/login"
),
req
);
});

app.post("/login", authLimiter, async (req, res, next) => {
try {
const email = emailNormal(req.body.email);
const password = req.body.password;

if (!validEmail(email) ||
    typeof password !== "string" ||
    Buffer.byteLength(password, "utf8") > 72) {
  return flashRedirect(
    res,
    "/login",
    "Invalid email or password."
  );
}

const user = await get(
  "SELECT id, name, email, password_hash FROM users WHERE email = ?",
  [email]
);

const matches = user
  ? await bcrypt.compare(password, user.password_hash)
  : false;

if (!matches) {
  return flashRedirect(
    res,
    "/login",
    "Invalid email or password."
  );
}

await regenerateSession(req);

req.session.user = {
  id: user.id,
  name: user.name,
  email: user.email
};

await saveSession(req);

res.redirect("/dashboard");

} catch (error) {
next(error);
}
});

// --------------------------------------------------
// GREEN MEMBER DASHBOARD
// --------------------------------------------------

app.get("/dashboard", requireLogin, async (req, res, next) => {
try {
const user = req.session.user;

const content = `
  <section class="dashboard-shell">
    <div class="dashboard">

      <aside class="sidebar">
        <h3>YJIK MEMBER PORTAL</h3>

        <a class="active" href="/dashboard">▦ Dashboard</a>
        <a href="/about">♧ About YJIK</a>
        <a href="/programmes">◎ Programmes</a>
        <a href="/contact">✉ Contact Us</a>
        <a href="/donate">♡ Support Our Work</a>
        <a href="/privacy">▤ Privacy</a>

        <a href="/logout">↪ Logout</a>
      </aside>

      <div class="dash-main">
        <div class="dash-heading">
          <span class="eyebrow">MEMBER PORTAL</span>

          <h1>
            Welcome, ${escapeHTML(user.name)}!
          </h1>

          <p>
            Welcome to your Youth Justice Initiative Kenya
            member dashboard.
          </p>
        </div>

        <div class="stat-grid">
          <div class="stat-card">
            <strong>YJIK</strong>
            <span>Your community initiative</span>
          </div>

          <div class="stat-card">
            <strong>Rights</strong>
            <span>Awareness and access to justice</span>
          </div>

          <div class="stat-card">
            <strong>Growth</strong>
            <span>Learning and empowerment</span>
          </div>
        </div>

        <section class="dash-panel">
          <h2>Your Account</h2>

          <p>
            <strong>Full name:</strong>
            ${escapeHTML(user.name)}
          </p>

          <p>
            <strong>Email:</strong>
            ${escapeHTML(user.email)}
          </p>

          <p>
            <strong>Account ID:</strong>
            ${Number(user.id)}
          </p>

          <p>
            Your account allows you to access this member portal.
            It does not automatically confer organisational
            membership, an official position, or authority to
            represent the initiative.
          </p>
        </section>

        <section class="dash-panel">
          <h2>Explore Youth Justice Initiative Kenya</h2>

          <div class="action-grid">
            <div class="action-card">
              <h3>Youth Rights</h3>
              <p>
                Learn about our rights-awareness objectives
                and approach.
              </p>
              <a href="/about">Learn more →</a>
            </div>

            <div class="action-card">
              <h3>Our Programmes</h3>
              <p>
                Explore our intended work in justice,
                community safety and empowerment.
              </p>
              <a href="/programmes">Explore programmes →</a>
            </div>

            <div class="action-card">
              <h3>Contact the Initiative</h3>
              <p>
                Send an enquiry about volunteering,
                collaboration or our work.
              </p>
              <a href="/contact">Contact us →</a>
            </div>

            <div class="action-card">
              <h3>Support Our Work</h3>
              <p>
                Submit a donation pledge to indicate
                your intended contribution.
              </p>
              <a href="/donate">Support YJIK →</a>
            </div>
          </div>
        </section>

        <section class="dash-panel">
          <h2>Our Commitment</h2>

          <p>
            We aim to encourage dignity, fairness,
            accountability, inclusion and meaningful
            youth participation.
          </p>

          <form method="POST" action="/logout">
            <button class="button" type="submit">Log Out</button>
          </form>
        </section>
      </div>
    </div>
  </section>
`;

sendPage(res, "Member Dashboard", content, req);

} catch (error) {
next(error);
}
});

// --------------------------------------------------
// LOGOUT
// --------------------------------------------------

app.get("/logout", (req, res) => {
res.redirect("/dashboard");
});

app.post("/logout", async (req, res, next) => {
try {
await destroySession(req);

res.clearCookie("yjik.sid", {
  path: "/",
  httpOnly: true,
  secure: PRODUCTION,
  sameSite: "lax"
});

res.redirect("/");

} catch (error) {
next(error);
}
});

// --------------------------------------------------
// FORGOT PASSWORD
// --------------------------------------------------

app.get("/forgot-password", (req, res) => {
const fields = "<div class="field"> <label for="email">Email address</label> <input id="email" name="email" type="email" maxlength="254" autocomplete="email" required> </div>";

sendPage(
res,
"Forgot Password",
formPage(
"Forgot Your Password?",
"Enter your email address to request a password reset.",
fields,
"Send Reset Instructions",
"/forgot-password"
),
req
);
});

app.post(
"/forgot-password",
formLimiter,
async (req, res, next) => {
try {
const email = emailNormal(req.body.email);

  const genericMessage =
    "If an account exists for that email, reset instructions will be sent.";

  if (!validEmail(email)) {
    return flashRedirect(
      res,
      "/forgot-password",
      genericMessage
    );
  }

  const user = await get(
    "SELECT id, name, email FROM users WHERE email = ?",
    [email]
  );

  if (user) {
    await run(
      "DELETE FROM password_resets WHERE user_id = ?",
      [user.id]
    );

    const token = crypto.randomBytes(32).toString("hex");

    const tokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const expires = Date.now() + 15 * 60 * 1000;

    await run(
      `INSERT INTO password_resets
       (user_id, token_hash, expires_at)
       VALUES (?, ?, ?)`,
      [user.id, tokenHash, expires]
    );

    const link = publicURL(
      req,
      "/reset-password?token=" + token
    );

    try {
      await sendEmail({
        to: user.email,
        subject: "Reset your YJIK password",

        text:
          "Hello " + user.name + ",\n\n" +
          "Use this link within 15 minutes to reset your password:\n" +
          link + "\n\n" +
          "If you did not request this, ignore this email.",

        html:
          `<p>Hello ${escapeHTML(user.name)},</p>` +
          `<p>Use the link below within 15 minutes.</p>` +
          `<p><a href="${escapeHTML(link)}">Reset password</a></p>` +
          `<p>If you did not request this, ignore this email.</p>`
      });
    } catch (mailError) {
      console.error(
        "Password reset email failed:",
        mailError.message
      );
    }
  }

  flashRedirect(res, "/forgot-password", genericMessage);
} catch (error) {
  next(error);
}

}
);

// --------------------------------------------------
// RESET PASSWORD
// --------------------------------------------------

app.get("/reset-password", async (req, res, next) => {
try {
const token = String(req.query.token || "");

if (!/^[a-f0-9]{64}$/.test(token)) {
  return sendPage(
    res,
    "Reset Password",
    `
      <section class="form-wrap">
        <h1>Invalid Reset Link</h1>
        <p>Request a new password-reset link.</p>
        <a class="button" href="/forgot-password">Try Again</a>
      </section>
    `,
    req,
    400
  );
}

const hash = crypto
  .createHash("sha256")
  .update(token)
  .digest("hex");

const record = await get(
  `SELECT id FROM password_resets
   WHERE token_hash = ? AND expires_at > ?`,
  [hash, Date.now()]
);

if (!record) {
  return sendPage(
    res,
    "Reset Password",
    `
      <section class="form-wrap">
        <h1>Reset Link Expired</h1>
        <p>Request a new password-reset link.</p>
        <a class="button" href="/forgot-password">Request New Link</a>
      </section>
    `,
    req,
    400
  );
}

const fields = `
  <input type="hidden" name="token"
    value="${escapeHTML(token)}">

  <div class="field">
    <label for="password">New password</label>
    <input id="password" name="password" type="password"
      minlength="12" maxlength="72"
      autocomplete="new-password" required>
  </div>

  <div class="field">
    <label for="confirmPassword">Confirm password</label>
    <input id="confirmPassword" name="confirmPassword"
      type="password" minlength="12" maxlength="72"
      autocomplete="new-password" required>
  </div>
`;

res.set("Referrer-Policy", "no-referrer");

sendPage(
  res,
  "Reset Password",
  formPage(
    "Choose a New Password",
    "Your password reset link expires after 15 minutes.",
    fields,
    "Update Password",
    "/reset-password"
  ),
  req
);

} catch (error) {
next(error);
}
});

app.post(
"/reset-password",
formLimiter,
async (req, res, next) => {
try {
const token = String(req.body.token || "");
const password = req.body.password;

  if (!/^[a-f0-9]{64}$/.test(token) ||
      !validPassword(password) ||
      password !== req.body.confirmPassword) {
    return res.status(400).send(
      "Invalid token or password. Request a new reset link if needed."
    );
  }

  const hash = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

  const record = await get(
    `SELECT id, user_id FROM password_resets
     WHERE token_hash = ? AND expires_at > ?`,
    [hash, Date.now()]
  );

  if (!record) {
    return res.status(400).send(
      "The password reset link is invalid or expired."
    );
  }

  const passwordHash = await bcrypt.hash(password, 12);

  await run(
    "UPDATE users SET password_hash = ? WHERE id = ?",
    [passwordHash, record.user_id]
  );

  await run(
    "DELETE FROM password_resets WHERE user_id = ?",
    [record.user_id]
  );

  flashRedirect(
    res,
    "/login",
    "Password updated. Please log in with your new password."
  );
} catch (error) {
  next(error);
}

}
);

// --------------------------------------------------
// CONTACT
// --------------------------------------------------

app.get("/contact", (req, res) => {
const fields = `
<div class="field">
<label for="name">Full name</label>
<input id="name" name="name" maxlength="100" required>
</div>

<div class="field">
  <label for="email">Email address</label>
  <input id="email" name="email" type="email"
    maxlength="254" required>
</div>

<div class="field">
  <label for="subject">Subject</label>
  <input id="subject" name="subject"
    maxlength="150" required>
</div>

<div class="field">
  <label for="message">Message</label>
  <textarea id="message" name="message"
    minlength="10" maxlength="5000" required></textarea>
</div>

`;

const content = `
${pageHeader(
"Contact Us",
"Enquiries about our work, partnerships, volunteering and support."
)}

<section class="section">
  <div class="grid two">
    <article class="card">
      <h2>Get in Touch</h2>

      <p>
        We welcome enquiries from young people, community members,
        civil society organisations, volunteers and potential partners.
      </p>

      <p>
        <strong>Community location</strong><br>
        Lurende Market, Khatiri, Bungoma County, Kenya.
      </p>

      <p>
        <strong>Email</strong><br>
        ${
          process.env.CONTACT_EMAIL
            ? `<a href="mailto:${escapeHTML(process.env.CONTACT_EMAIL)}">${
                escapeHTML(process.env.CONTACT_EMAIL)
              }</a>`
            : "Contact email has not yet been configured."
        }
      </p>

      <p>
        Do not submit passwords, confidential legal documents or
        sensitive information through this general contact form.
      </p>
    </article>

    <div>
      ${formPage(
        "Send a Message",
        "Complete the form below.",
        fields,
        "Send Message",
        "/contact"
      )}
    </div>
  </div>
</section>

`;

sendPage(res, "Contact Us", content, req);
});

app.post("/contact", formLimiter, async (req, res, next) => {
try {
const name = String(req.body.name || "").trim();
const email = emailNormal(req.body.email);
const subject = String(req.body.subject || "").trim();
const message = String(req.body.message || "").trim();

if (name.length < 2 || name.length > 100 ||
    !validEmail(email) ||
    subject.length < 2 || subject.length > 150 ||
    message.length < 10 || message.length > 5000) {
  return res.status(400).send(
    "Please check your contact details and try again."
  );
}

await run(
  `INSERT INTO contact_messages
   (name, email, subject, message)
   VALUES (?, ?, ?, ?)`,
  [name, email, subject, message]
);

if (process.env.CONTACT_EMAIL) {
  try {
    await sendEmail({
      to: process.env.CONTACT_EMAIL,
      subject: "YJIK enquiry: " + subject,

      text:
        "Name: " + name + "\n" +
        "Email: " + email + "\n\n" +
        message
    });
  } catch (error) {
    console.error("Contact notification failed:", error.message);
  }
}

flashRedirect(
  res,
  "/contact",
  "Thank you. Your message has been recorded."
);

} catch (error) {
next(error);
}
});

// --------------------------------------------------
// DONATIONS
// --------------------------------------------------

app.get("/donate", (req, res) => {
const fields = `
<div class="field">
<label for="name">Full name</label>
<input id="name" name="name" maxlength="100" required>
</div>

<div class="field">
  <label for="email">Email address</label>
  <input id="email" name="email" type="email"
    maxlength="254" required>
</div>

<div class="field">
  <label for="amount">Pledge amount (KES)</label>
  <input id="amount" name="amount" type="number"
    min="1" max="10000000" step="1" required>
</div>

<div class="field">
  <label for="programme">Programme</label>
  <select id="programme" name="programme" required>
    <option value="">Select a programme</option>
    <option>Youth Rights Awareness</option>
    <option>Access to Justice</option>
    <option>Community Safety</option>
    <option>Youth Empowerment</option>
    <option>General Support</option>
  </select>
</div>

<div class="field">
  <label for="message">Message (optional)</label>
  <textarea id="message" name="message" maxlength="1000"></textarea>
</div>

`;

const content = `
${pageHeader(
"Support Our Work",
"Support our intended work in youth rights, justice and empowerment."
)}

<section class="section">
  <div class="grid two">
    <article class="card">
      <h2>How Support Can Help</h2>

      <p>
        Financial support may help the initiative develop educational
        materials, conduct outreach, share information about
        opportunities and strengthen partnerships.
      </p>

      <ul>
        <li>Youth rights education.</li>
        <li>Community awareness activities.</li>
        <li>Legal information and referral awareness.</li>
        <li>Youth empowerment activities.</li>
        <li>Responsible programme administration.</li>
      </ul>

      <p>
        Contributions should be handled through verified channels,
        with proper records and transparent reporting.
      </p>
    </article>

    <div>
      ${formPage(
        "Make a Donation Pledge",
        "Indicate the amount you intend to contribute.",
        fields,
        "Submit Pledge",
        "/donate"
      )}

      <p class="help">
        This form records a pledge only. It does not charge your
        account or process M-Pesa, bank or card payments.
      </p>
    </div>
  </div>
</section>

`;

sendPage(res, "Donate", content, req);
});

app.post("/donate", formLimiter, async (req, res, next) => {
try {
const name = String(req.body.name || "").trim();
const email = emailNormal(req.body.email);
const amount = Number(req.body.amount);
const programme = String(req.body.programme || "");
const message = String(req.body.message || "").trim();

const allowed = [
  "Youth Rights Awareness",
  "Access to Justice",
  "Community Safety",
  "Youth Empowerment",
  "General Support"
];

if (name.length < 2 || name.length > 100 ||
    !validEmail(email) ||
    !Number.isSafeInteger(amount) ||
    amount < 1 || amount > 10000000 ||
    !allowed.includes(programme) ||
    message.length > 1000) {
  return res.status(400).send(
    "Please check your donation pledge details."
  );
}

await run(
  `INSERT INTO donations
   (name, email, amount, programme, message, status)
   VALUES (?, ?, ?, ?, ?, 'pledged')`,
  [name, email, amount, programme, message]
);

sendPage(
  res,
  "Pledge Received",
  `
    <section class="form-wrap">
      <h1>Thank You for Your Support!</h1>

      <p>
        Your pledge of KES
        ${amount.toLocaleString("en-KE")}
        for ${escapeHTML(programme)} has been recorded.
      </p>

      <p>
        This is a pledge, not a completed payment.
        No money has been collected through this form.
      </p>

      <a class="button" href="/">Return Home</a>
    </section>
  `,
  req
);

} catch (error) {
next(error);
}
});

// --------------------------------------------------
// PRIVACY
// --------------------------------------------------

app.get("/privacy", (req, res) => {
const content = `
${pageHeader(
"Privacy Information",
"Information about how this website handles user data."
)}

<section class="section">
  <div class="content">
    <h2>Information Collected</h2>

    <p>
      Depending on how you use the website, it may collect your
      name, email address, password hash, contact enquiry and
      donation pledge details.
    </p>

    <h2>Purpose</h2>

    <p>
      Information may be used to manage accounts, answer enquiries,
      deliver password resets and record donation pledges.
    </p>

    <h2>Security</h2>

    <p>
      Passwords are hashed before storage. Access to personal data
      should be restricted to authorised persons.
    </p>

    <h2>Data Protection</h2>

    <p>
      Personal information must be handled in accordance with
      applicable Kenyan data protection law. Before launch,
      complete this notice with the organisation's actual data
      controller details, retention policy, lawful processing
      purposes, rights procedures and any third-party services.
    </p>

    <h2>Contact</h2>

    <p>
      For privacy questions, contact the organisation through
      the contact details published on this website.
    </p>
  </div>
</section>

`;

sendPage(res, "Privacy Information", content, req);
});

// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get("/health", async (req, res) => {
try {
await get("SELECT 1 AS ok");

res.json({
  status: "ok",
  application: "Youth Justice Initiative Kenya",
  database: "connected",
  timestamp: new Date().toISOString()
});

} catch (error) {
res.status(503).json({
status: "error",
database: "unavailable"
});
}
});

// --------------------------------------------------
// 404
// --------------------------------------------------

app.use((req, res) => {
sendPage(
res,
"Page Not Found",
"<section class="form-wrap"> <h1>404 - Page Not Found</h1> <p>The requested page could not be found.</p> <a class="button" href="/">Return Home</a> </section>",
req,
404
);
});

// --------------------------------------------------
// ERROR HANDLER
// --------------------------------------------------

app.use((error, req, res, next) => {
console.error("Application error:", error.message);

if (res.headersSent) return next(error);

sendPage(
res,
"Server Error",
"<section class="form-wrap"> <h1>Something Went Wrong</h1> <p>Please try again later.</p> <a class="button" href="/">Return Home</a> </section>",
req,
500
);
});

// --------------------------------------------------
// START
// --------------------------------------------------

async function start() {
try {
await initialiseDatabase();

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    "Youth Justice Initiative Kenya running on port " + PORT
  );
});

} catch (error) {
console.error("Startup failed:", error);
process.exit(1);
}
}

start();
