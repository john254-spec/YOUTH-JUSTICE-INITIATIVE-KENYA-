"use strict";

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 10000;
const NODE_ENV = process.env.NODE_ENV || "development";
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const SESSION_SECRET =
  process.env.SESSION_SECRET || "development-only-change-this-secret";

if (NODE_ENV === "production" && SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must contain at least 32 characters in production.");
}

fs.mkdirSync(DATA_DIR, { recursive: true });

/* =========================================================
   DATABASE
========================================================= */

const db = new Database(path.join(DATA_DIR, "yjik.sqlite"));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS contact_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS donation_pledges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    amount REAL NOT NULL,
    message TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Pledge received',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

/* =========================================================
   SECURITY AND MIDDLEWARE
========================================================= */

// Trust Render's HTTPS reverse proxy.
// This must be set before session middleware.
if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'", "https:", "data:"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests:
          NODE_ENV === "production" ? [] : null
      }
    }
  })
);

app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 200,
    standardHeaders: "draft-7",
    legacyHeaders: false
  })
);

app.use(
  session({
    name: "yjik.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 8
    }
  })
);

/* =========================================================
   EMAIL CONFIGURATION
========================================================= */

let transporter = null;

if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || "false") === "true",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

/* =========================================================
   HELPER FUNCTIONS
========================================================= */

function escapeHTML(value = "") {
  const entities = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  };

  return String(value).replace(/[&<>"']/g, ch => entities[ch]);
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function publicURL(req) {
  if (process.env.BASE_URL) {
    return process.env.BASE_URL.replace(/\/+$/, "");
  }

  return `${req.protocol}://${req.get("host")}`;
}

function currentUser(req) {
  if (!req.session.userId) {
    return null;
  }

  return (
    db
      .prepare("SELECT id, name, email, created_at FROM users WHERE id = ?")
      .get(req.session.userId) || null
  );
}

function requireLogin(req, res, next) {
  if (!req.session.userId || !currentUser(req)) {
    return res.redirect("/login?message=" + encodeURIComponent("Please log in first."));
  }

  next();
}

function redirectMessage(res, pathName, message) {
  return res.redirect(
    `${pathName}?message=${encodeURIComponent(message)}`
  );
}

function pageHeader(title, description) {
  return `
    <section class="page-header">
      <h1>${escapeHTML(title)}</h1>
      <p>${escapeHTML(description)}</p>
    </section>
  `;
}

function renderPage(req, title, content) {
  const user = currentUser(req);

  const nav = user
    ? `
      <a href="/dashboard">Dashboard</a>
      <form method="POST" action="/logout" class="logout-form">
        <button type="submit" class="nav-join">Logout</button>
      </form>
    `
    : `
      <a href="/login">Login</a>
      <a class="nav-join" href="/signup">Join Us</a>
    `;

  const notice = req.query.message
    ? `<div class="notice" role="status">${escapeHTML(req.query.message)}</div>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Youth Justice Initiative Kenya promotes youth rights, access to justice, legal awareness, community safety and youth empowerment.">
  <title>${escapeHTML(title)} | Youth Justice Initiative Kenya</title>

  <style>
    :root {
      --green: #126b3a;
      --dark-green: #084526;
      --light-green: #eaf5ee;
      --gold: #f2c94c;
      --text: #202a24;
      --muted: #627067;
      --border: #dce5de;
      --background: #f7faf8;
      --white: #ffffff;
      --danger: #a61b1b;
    }

    * {
      box-sizing: border-box;
    }

    html {
      scroll-behavior: smooth;
    }

    body {
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      line-height: 1.65;
      color: var(--text);
      background: var(--background);
    }

    a {
      color: var(--green);
    }

    .container {
      width: min(1120px, 92%);
      margin: 0 auto;
    }

    header {
      background: var(--white);
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      z-index: 10;
    }

    .navbar {
      min-height: 76px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
    }

    .brand {
      color: var(--dark-green);
      font-weight: 800;
      font-size: 17px;
      line-height: 1.3;
      text-decoration: none;
      max-width: 290px;
    }

    .nav-links {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .nav-links a {
      text-decoration: none;
      font-weight: 600;
    }

    .nav-join {
      display: inline-block;
      background: var(--green);
      color: var(--white);
      border: 0;
      border-radius: 6px;
      padding: 10px 16px;
      text-decoration: none;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
    }

    .logout-form {
      display: inline;
      margin: 0;
    }

    .menu-toggle {
      display: none;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 12px;
      background: var(--white);
      cursor: pointer;
    }

    main {
      min-height: 70vh;
    }

    .hero {
      padding: 90px 0;
      color: var(--white);
      background: linear-gradient(135deg, var(--dark-green), var(--green));
    }

    .hero h1 {
      max-width: 800px;
      font-size: clamp(34px, 5vw, 58px);
      line-height: 1.15;
      margin: 0 0 20px;
    }

    .hero p {
      max-width: 760px;
      font-size: 19px;
      margin-bottom: 28px;
    }

    .hero .button {
      background: var(--gold);
      color: #183b26;
    }

    .button {
      display: inline-block;
      padding: 12px 20px;
      border: 0;
      border-radius: 6px;
      background: var(--green);
      color: var(--white);
      text-decoration: none;
      font-weight: 700;
      cursor: pointer;
      font-size: 15px;
    }

    .button-secondary {
      background: var(--white);
      color: var(--green);
      border: 1px solid var(--green);
    }

    .section {
      padding: 55px 0;
    }

    .section h2 {
      color: var(--dark-green);
      line-height: 1.25;
    }

    .section-intro {
      max-width: 780px;
      color: var(--muted);
    }

    .page-header {
      padding: 50px 4%;
      text-align: center;
      background: var(--light-green);
    }

    .page-header h1 {
      margin: 0 0 8px;
      color: var(--dark-green);
      font-size: clamp(30px, 4vw, 44px);
    }

    .page-header p {
      margin: 0;
      color: var(--muted);
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 22px;
    }

    .card {
      background: var(--white);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 24px;
      box-shadow: 0 5px 18px rgba(0, 0, 0, 0.03);
    }

    .card h3 {
      margin-top: 0;
      color: var(--dark-green);
    }

    .form-wrap {
      max-width: 650px;
      margin: 42px auto;
      padding: 30px;
      background: var(--white);
      border: 1px solid var(--border);
      border-radius: 10px;
    }

    .form-wrap h1,
    .form-wrap h2 {
      color: var(--dark-green);
    }

    .field {
      margin-bottom: 18px;
    }

    .field label {
      display: block;
      margin-bottom: 6px;
      font-weight: 700;
    }

    .field input,
    .field textarea,
    .field select {
      width: 100%;
      padding: 12px;
      border: 1px solid #bdcbc0;
      border-radius: 6px;
      font: inherit;
      background: var(--white);
    }

    .field textarea {
      min-height: 130px;
      resize: vertical;
    }

    .notice {
      max-width: 1000px;
      width: 92%;
      margin: 20px auto 0;
      padding: 12px 16px;
      background: var(--light-green);
      border-left: 4px solid var(--green);
      border-radius: 4px;
      overflow-wrap: anywhere;
    }

    .dashboard-card {
      background: var(--white);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 24px;
      margin-bottom: 20px;
    }

    .dashboard-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 20px;
    }

    .muted {
      color: var(--muted);
    }

    footer {
      background: #102d1d;
      color: var(--white);
      padding: 35px 0;
      margin-top: 40px;
    }

    footer a {
      color: #d9f3e1;
    }

    .footer-grid {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 25px;
    }

    .small {
      font-size: 14px;
    }

    @media (max-width: 850px) {
      .menu-toggle {
        display: inline-block;
      }

      .navbar {
        flex-wrap: wrap;
        padding: 14px 0;
      }

      .nav-links {
        display: none;
        width: 100%;
        align-items: flex-start;
        flex-direction: column;
        padding: 12px 0;
      }

      .nav-links.open {
        display: flex;
      }

      .grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }

    @media (max-width: 560px) {
      .grid,
      .footer-grid {
        grid-template-columns: 1fr;
      }

      .hero {
        padding: 60px 0;
      }

      .form-wrap {
        width: 92%;
        padding: 22px;
      }
    }
  </style>
</head>

<body>
  <header>
    <div class="container navbar">
      <a class="brand" href="/">Youth Justice Initiative Kenya</a>

      <button
        id="menuToggle"
        class="menu-toggle"
        type="button"
        aria-expanded="false"
        aria-controls="navLinks"
      >Menu ☰</button>

      <nav id="navLinks" class="nav-links" aria-label="Main navigation">
        <a href="/">Home</a>
        <a href="/about">About</a>
        <a href="/programmes">Programmes</a>
        <a href="/contact">Contact</a>
        <a href="/donate">Support Us</a>
        ${nav}
      </nav>
    </div>
  </header>

  ${notice}

  <main>
    ${content}
  </main>

  <footer>
    <div class="container footer-grid">
      <div>
        <h3>Youth Justice Initiative Kenya</h3>
        <p>
          Promoting youth rights, legal awareness, access to justice,
          community safety and youth empowerment.
        </p>
      </div>

      <div>
        <h3>Quick Links</h3>
        <p><a href="/about">About Us</a></p>
        <p><a href="/programmes">Our Programmes</a></p>
        <p><a href="/contact">Contact Us</a></p>
        <p><a href="/privacy">Privacy Policy</a></p>
      </div>
    </div>

    <div class="container small">
      <p>
        &copy; ${new Date().getFullYear()} Youth Justice Initiative Kenya.
        All rights reserved.
      </p>
    </div>
  </footer>

  <script>
    const menuToggle = document.getElementById("menuToggle");
    const navLinks = document.getElementById("navLinks");

    if (menuToggle && navLinks) {
      menuToggle.addEventListener("click", function () {
        const isOpen = navLinks.classList.toggle("open");
        menuToggle.setAttribute("aria-expanded", String(isOpen));
      });
    }
  </script>
</body>
</html>`;
}

function formPage(req, title, description, fields, submitLabel) {
  return renderPage(
    req,
    title,
    `
      ${pageHeader(title, description)}

      <section class="form-wrap">
        <form method="POST">
          ${fields}
          <button class="button" type="submit">${escapeHTML(submitLabel)}</button>
        </form>
      </section>
    `
  );
}

function sendEmail(options) {
  if (!transporter) {
    return Promise.resolve(false);
  }

  return transporter.sendMail(options).then(
    () => true,
    error => {
      console.error("Email delivery failed:", error.message);
      return false;
    }
  );
}

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/health", (req, res) => {
  try {
    db.prepare("SELECT 1").get();

    res.status(200).json({
      status: "ok",
      service: "Youth Justice Initiative Kenya",
      database: "connected",
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error("Health check failed:", error.message);

    res.status(500).json({
      status: "error",
      database: "unavailable"
    });
  }
});

/* =========================================================
   HOME PAGE
========================================================= */

app.get("/", (req, res) => {
  const content = `
    <section class="hero">
      <div class="container">
        <h1>Justice, Dignity and Opportunity for Every Young Person</h1>

        <p>
          Youth Justice Initiative Kenya works to promote youth rights,
          legal awareness, access to justice, community safety and
          opportunities for young people.
        </p>

        <a class="button" href="/about">Learn About Us</a>
        <a class="button button-secondary" href="/signup">Join Our Community</a>
      </div>
    </section>

    <section class="section">
      <div class="container">
        <h2>Who We Are</h2>

        <p class="section-intro">
          We seek to empower young people with knowledge of their rights,
          information about justice processes, and connections to
          constructive opportunities within their communities.
        </p>

        <div class="grid">
          <article class="card">
            <h3>Youth Rights</h3>
            <p>
              Promote awareness of the rights, responsibilities and
              protections available to young people.
            </p>
          </article>

          <article class="card">
            <h3>Access to Justice</h3>
            <p>
              Share legal information and help young people identify
              appropriate channels for seeking assistance.
            </p>
          </article>

          <article class="card">
            <h3>Youth Empowerment</h3>
            <p>
              Connect young people with relevant educational,
              livelihood and community development opportunities.
            </p>
          </article>
        </div>
      </div>
    </section>

    <section class="section" style="background:#eaf5ee">
      <div class="container">
        <h2>Be Part of the Change</h2>

        <p>
          Join our community, share an idea, volunteer your skills
          or discuss a potential partnership.
        </p>

        <a class="button" href="/signup">Become a Member</a>
        <a class="button button-secondary" href="/contact">Contact Us</a>
      </div>
    </section>
  `;

  res.send(renderPage(req, "Home", content));
});

/* =========================================================
   ABOUT PAGE
========================================================= */

app.get("/about", (req, res) => {
  const content = `
    ${pageHeader(
      "About Us",
      "Promoting youth rights, justice, safety and empowerment."
    )}

    <section class="section">
      <div class="container">
        <h2>Our Purpose</h2>

        <p>
          Youth Justice Initiative Kenya is a community-oriented initiative
          focused on youth rights awareness, legal awareness, fair treatment
          within the justice system and access to appropriate support.
        </p>

        <h2>Our Vision</h2>

        <p>
          A society where young people understand their rights, access
          justice fairly and participate meaningfully in community life.
        </p>

        <h2>Our Mission</h2>

        <p>
          To promote youth rights, legal awareness, access to justice,
          community safety and youth empowerment through education,
          outreach, collaboration and advocacy.
        </p>

        <h2>Our Values</h2>

        <div class="grid">
          <article class="card">
            <h3>Dignity</h3>
            <p>Respect for every person's dignity and rights.</p>
          </article>

          <article class="card">
            <h3>Accountability</h3>
            <p>Responsible conduct, transparency and ethical practice.</p>
          </article>

          <article class="card">
            <h3>Inclusion</h3>
            <p>Meaningful participation of young people in community affairs.</p>
          </article>
        </div>
      </div>
    </section>
  `;

  res.send(renderPage(req, "About Us", content));
});

/* =========================================================
   PROGRAMMES PAGE
========================================================= */

app.get("/programmes", (req, res) => {
  const programmes = [
    [
      "Youth Rights Awareness",
      "Community education on human rights, constitutional rights and the responsibilities of young people."
    ],
    [
      "Legal Awareness and Access to Justice",
      "General legal information and referrals to qualified advocates, legal aid providers and appropriate authorities."
    ],
    [
      "Community Safety",
      "Constructive engagement with communities and relevant stakeholders to promote safety, prevention and peaceful conflict resolution."
    ],
    [
      "Child Protection and Youth Welfare",
      "Awareness of child protection, safeguarding and appropriate reporting or referral channels."
    ],
    [
      "Youth Empowerment",
      "Sharing information about education, employment, skills development and other opportunities."
    ],
    [
      "Advocacy and Youth Participation",
      "Encouraging young people to participate in decision-making and community development."
    ]
  ];

  const cards = programmes
    .map(
      item => `
        <article class="card">
          <h3>${escapeHTML(item[0])}</h3>
          <p>${escapeHTML(item[1])}</p>
        </article>
      `
    )
    .join("");

  const content = `
    ${pageHeader(
      "Our Programmes",
      "Building knowledge, opportunity and safer communities."
    )}

    <section class="section">
      <div class="container">
        <div class="grid">
          ${cards}
        </div>
      </div>
    </section>
  `;

  res.send(renderPage(req, "Programmes", content));
});

/* =========================================================
   CONTACT PAGE
========================================================= */

app.get("/contact", (req, res) => {
  const fields = `
    <div class="field">
      <label for="name">Full name</label>
      <input id="name" name="name" type="text" maxlength="100" required>
    </div>

    <div class="field">
      <label for="email">Email address</label>
      <input id="email" name="email" type="email" maxlength="254" required>
    </div>

    <div class="field">
      <label for="subject">Subject</label>
      <input id="subject" name="subject" type="text" maxlength="150" required>
    </div>

    <div class="field">
      <label for="message">Message</label>
      <textarea id="message" name="message" maxlength="5000" required></textarea>
    </div>
  `;

  res.send(
    formPage(
      req,
      "Contact Us",
      "Send us a question, suggestion or partnership enquiry.",
      fields,
      "Send Message"
    )
  );
});

app.post("/contact", (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const subject = String(req.body.subject || "").trim();
  const message = String(req.body.message || "").trim();

  if (
    !name ||
    !validEmail(email) ||
    !subject ||
    !message ||
    name.length > 100 ||
    email.length > 254 ||
    subject.length > 150 ||
    message.length > 5000
  ) {
    return redirectMessage(
      res,
      "/contact",
      "Please provide valid details in all fields."
    );
  }

  try {
    db.prepare(`
      INSERT INTO contact_messages (name, email, subject, message)
      VALUES (?, ?, ?, ?)
    `).run(name, email, subject, message);

    console.log("New contact message received.");

    return redirectMessage(
      res,
      "/contact",
      "Thank you. Your message has been received."
    );
  } catch (error) {
    console.error("Contact message database error:", error.message);

    return redirectMessage(
      res,
      "/contact",
      "We could not save your message. Please try again later."
    );
  }
});

/* =========================================================
   DONATION / SUPPORT PAGE
   This records pledges only. It does not process payments.
========================================================= */

app.get("/donate", (req, res) => {
  const fields = `
    <div class="field">
      <label for="name">Full name</label>
      <input id="name" name="name" type="text" maxlength="100" required>
    </div>

    <div class="field">
      <label for="email">Email address</label>
      <input id="email" name="email" type="email" maxlength="254" required>
    </div>

    <div class="field">
      <label for="amount">Pledge amount (KES)</label>
      <input id="amount" name="amount" type="number" min="1" max="100000000" step="1" required>
    </div>

    <div class="field">
      <label for="message">Message (optional)</label>
      <textarea id="message" name="message" maxlength="1000"></textarea>
    </div>
  `;

  const content = `
    ${pageHeader(
      "Support Our Work",
      "Help support youth rights awareness, access to justice and empowerment."
    )}

    <section class="form-wrap">
      <h2>Make a Pledge</h2>

      <p class="muted">
        This form records an expression of support. It does not collect
        payment details or transfer money. Payment arrangements must be
        confirmed separately through an authorized channel.
      </p>

      <form method="POST">
        ${fields}
        <button class="button" type="submit">Submit Pledge</button>
      </form>
    </section>
  `;

  res.send(renderPage(req, "Support Us", content));
});

app.post("/donate", (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const amount = Number(req.body.amount);
  const message = String(req.body.message || "").trim();

  if (
    !name ||
    name.length > 100 ||
    !validEmail(email) ||
    email.length > 254 ||
    !Number.isFinite(amount) ||
    amount < 1 ||
    amount > 100000000 ||
    !Number.isInteger(amount) ||
    message.length > 1000
  ) {
    return redirectMessage(
      res,
      "/donate",
      "Please provide valid pledge details."
    );
  }

  try {
    db.prepare(`
      INSERT INTO donation_pledges (name, email, amount, message)
      VALUES (?, ?, ?, ?)
    `).run(name, email, amount, message);

    console.log("A new support pledge was recorded.");

    return redirectMessage(
      res,
      "/donate",
      "Thank you for your support pledge. This form has not processed a payment."
    );
  } catch (error) {
    console.error("Pledge database error:", error.message);

    return redirectMessage(
      res,
      "/donate",
      "We could not record your pledge. Please try again."
    );
  }
});

/* =========================================================
   SIGNUP
========================================================= */

app.get("/signup", (req, res) => {
  if (currentUser(req)) {
    return res.redirect("/dashboard");
  }

  const fields = `
    <div class="field">
      <label for="name">Full name</label>
      <input
        id="name"
        name="name"
        type="text"
        maxlength="100"
        autocomplete="name"
        required
      >
    </div>

    <div class="field">
      <label for="email">Email address</label>
      <input
        id="email"
        name="email"
        type="email"
        maxlength="254"
        autocomplete="email"
        required
      >
    </div>

    <div class="field">
      <label for="password">Password</label>
      <input
        id="password"
        name="password"
        type="password"
        minlength="8"
        maxlength="128"
        autocomplete="new-password"
        required
      >
      <small>Use at least 8 characters.</small>
    </div>
  `;

  res.send(
    formPage(
      req,
      "Create an Account",
      "Join the Youth Justice Initiative Kenya online community.",
      fields,
      "Create Account"
    )
  );
});

app.post("/signup", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (
    !name ||
    name.length > 100 ||
    !validEmail(email) ||
    email.length > 254 ||
    password.length < 8 ||
    password.length > 128
  ) {
    return redirectMessage(
      res,
      "/signup",
      "Enter a valid name and email, and use a password of at least 8 characters."
    );
  }

  try {
    const existingUser = db
      .prepare("SELECT id FROM users WHERE email = ?")
      .get(email);

    if (existingUser) {
      return redirectMessage(
        res,
        "/signup",
        "An account with that email already exists. Please log in."
      );
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (name, email, password_hash)
      VALUES (?, ?, ?)
    `).run(name, email, passwordHash);

    req.session.regenerate(error => {
      if (error) {
        console.error("Session regeneration error:", error.message);

        return redirectMessage(
          res,
          "/login",
          "Your account was created. Please log in."
        );
      }

      req.session.userId = Number(result.lastInsertRowid);

      req.session.save(saveError => {
        if (saveError) {
          console.error("Session save error:", saveError.message);

          return redirectMessage(
            res,
            "/login",
            "Your account was created. Please log in."
          );
        }

        res.redirect("/dashboard");
      });
    });
  } catch (error) {
    console.error("Signup error:", error.message);

    return redirectMessage(
      res,
      "/signup",
      "We could not create your account. Please try again."
    );
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.get("/login", (req, res) => {
  if (currentUser(req)) {
    return res.redirect("/dashboard");
  }

  const fields = `
    <div class="field">
      <label for="email">Email address</label>
      <input
        id="email"
        name="email"
        type="email"
        maxlength="254"
        autocomplete="email"
        required
      >
    </div>

    <div class="field">
      <label for="password">Password</label>
      <input
        id="password"
        name="password"
        type="password"
        maxlength="128"
        autocomplete="current-password"
        required
      >
    </div>

    <p><a href="/forgot-password">Forgot your password?</a></p>
    <p>New here? <a href="/signup">Create an account</a>.</p>
  `;

  res.send(
    formPage(
      req,
      "Login",
      "Log in to access your member dashboard.",
      fields,
      "Login"
    )
  );
});

app.post("/login", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!validEmail(email) || password.length > 128 || !password) {
    return redirectMessage(
      res,
      "/login",
      "Invalid email or password."
    );
  }

  try {
    const user = db
      .prepare("SELECT id, password_hash FROM users WHERE email = ?")
      .get(email);

    const passwordMatches =
      user && (await bcrypt.compare(password, user.password_hash));

    if (!passwordMatches) {
      return redirectMessage(
        res,
        "/login",
        "Invalid email or password."
      );
    }

    req.session.regenerate(error => {
      if (error) {
        console.error("Login session error:", error.message);

        return redirectMessage(
          res,
          "/login",
          "Login failed. Please try again."
        );
      }

      req.session.userId = user.id;

      req.session.save(saveError => {
        if (saveError) {
          console.error("Login session save error:", saveError.message);

          return redirectMessage(
            res,
            "/login",
            "Login failed. Please try again."
          );
        }

        res.redirect("/dashboard");
      });
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return redirectMessage(
      res,
      "/login",
      "We could not log you in. Please try again."
    );
  }
});

/* =========================================================
   MEMBER DASHBOARD
========================================================= */

app.get("/dashboard", requireLogin, (req, res) => {
  const user = currentUser(req);

  if (!user) {
    return res.redirect("/login");
  }

  const content = `
    ${pageHeader(
      "Member Dashboard",
      "Welcome to your Youth Justice Initiative Kenya account."
    )}

    <section class="section">
      <div class="container">
        <div class="dashboard-card">
          <h2>Welcome, ${escapeHTML(user.name)}!</h2>

          <p>
            You are logged in to the Youth Justice Initiative Kenya
            member area.
          </p>

          <p><strong>Name:</strong> ${escapeHTML(user.name)}</p>
          <p><strong>Email:</strong> ${escapeHTML(user.email)}</p>
          <p>
            <strong>Member since:</strong>
            ${escapeHTML(user.created_at)}
          </p>
        </div>

        <div class="dashboard-card">
          <h2>Get Involved</h2>

          <p>
            Explore our programmes, contact the initiative or share
            information about opportunities and potential partnerships.
          </p>

          <div class="dashboard-actions">
            <a class="button" href="/programmes">Explore Programmes</a>
            <a class="button" href="/contact">Contact Us</a>
            <a class="button button-secondary" href="/privacy">Privacy Policy</a>
          </div>
        </div>
      </div>
    </section>
  `;

  res.send(renderPage(req, "Member Dashboard", content));
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/logout", (req, res) => {
  req.session.destroy(error => {
    if (error) {
      console.error("Logout error:", error.message);
    }

    res.clearCookie("yjik.sid");
    res.redirect("/");
  });
});

/* =========================================================
   FORGOT PASSWORD
========================================================= */

app.get("/forgot-password", (req, res) => {
  const fields = `
    <div class="field">
      <label for="email">Email address</label>
      <input
        id="email"
        name="email"
        type="email"
        maxlength="254"
        autocomplete="email"
        required
      >
    </div>
  `;

  res.send(
    formPage(
      req,
      "Forgot Password",
      "Request a password reset link for your account.",
      fields,
      "Request Reset Link"
    )
  );
});

app.post("/forgot-password", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();

  if (!validEmail(email) || email.length > 254) {
    return redirectMessage(
      res,
      "/forgot-password",
      "If an account exists for that email, password reset instructions will be sent."
    );
  }

  try {
    const user = db
      .prepare("SELECT id, name, email FROM users WHERE email = ?")
      .get(email);

    if (user) {
      const rawToken = crypto.randomBytes(32).toString("hex");
      const tokenHash = crypto
        .createHash("sha256")
        .update(rawToken)
        .digest("hex");

      const expiresAt = Date.now() + 30 * 60 * 1000;

      db.prepare(`
        UPDATE password_resets
        SET used = 1
        WHERE user_id = ? AND used = 0
      `).run(user.id);

      db.prepare(`
        INSERT INTO password_resets (user_id, token_hash, expires_at)
        VALUES (?, ?, ?)
      `).run(user.id, tokenHash, expiresAt);

      const resetURL =
        `${publicURL(req)}/reset-password/${encodeURIComponent(rawToken)}`;

      const emailSent = await sendEmail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: user.email,
        subject: "Password Reset - Youth Justice Initiative Kenya",
        text:
          `Hello ${user.name},\n\n` +
          `A password reset was requested for your account.\n\n` +
          `Open this link within 30 minutes:\n${resetURL}\n\n` +
          `If you did not request this, you can ignore this email.`
      });

      if (!emailSent) {
        console.warn(
          "Password reset email could not be sent. Configure SMTP settings."
        );
      }
    }
  } catch (error) {
    console.error("Forgot-password error:", error.message);
  }

  return redirectMessage(
    res,
    "/forgot-password",
    "If an account exists for that email, password reset instructions will be sent."
  );
});

/* =========================================================
   RESET PASSWORD
========================================================= */

app.get("/reset-password/:token", (req, res) => {
  const token = String(req.params.token || "");

  if (!/^[a-f0-9]{64}$/i.test(token)) {
    return res.status(400).send(
      renderPage(
        req,
        "Invalid Reset Link",
        `
          <section class="form-wrap">
            <h1>Invalid Reset Link</h1>
            <p>This password reset link is invalid.</p>
            <a class="button" href="/forgot-password">Request Another Link</a>
          </section>
        `
      )
    );
  }

  const tokenHash = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

  const reset = db.prepare(`
    SELECT id
    FROM password_resets
    WHERE token_hash = ?
      AND used = 0
      AND expires_at > ?
  `).get(tokenHash, Date.now());

  if (!reset) {
    return res.status(400).send(
      renderPage(
        req,
        "Expired Reset Link",
        `
          <section class="form-wrap">
            <h1>Expired or Invalid Link</h1>
            <p>This reset link is no longer valid.</p>
            <a class="button" href="/forgot-password">Request Another Link</a>
          </section>
        `
      )
    );
  }

  const fields = `
    <input type="hidden" name="token" value="${escapeHTML(token)}">

    <div class="field">
      <label for="password">New password</label>
      <input
        id="password"
        name="password"
        type="password"
        minlength="8"
        maxlength="128"
        autocomplete="new-password"
        required
      >
    </div>

    <div class="field">
      <label for="confirmPassword">Confirm new password</label>
      <input
        id="confirmPassword"
        name="confirmPassword"
        type="password"
        minlength="8"
        maxlength="128"
        autocomplete="new-password"
        required
      >
    </div>
  `;

  res.send(
    formPage(
      req,
      "Reset Password",
      "Choose a new password for your account.",
      fields,
      "Update Password"
    )
  );
});

app.post("/reset-password/:token", async (req, res) => {
  const token = String(req.params.token || "");
  const password = String(req.body.password || "");
  const confirmPassword = String(req.body.confirmPassword || "");

  if (
    !/^[a-f0-9]{64}$/i.test(token) ||
    password.length < 8 ||
    password.length > 128 ||
    password !== confirmPassword
  ) {
    return redirectMessage(
      res,
      "/forgot-password",
      "The reset request was invalid. Request a new reset link and try again."
    );
  }

  try {
    const tokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const reset = db.prepare(`
      SELECT id, user_id
      FROM password_resets
      WHERE token_hash = ?
        AND used = 0
        AND expires_at > ?
    `).get(tokenHash, Date.now());

    if (!reset) {
      return redirectMessage(
        res,
        "/forgot-password",
        "This reset link is invalid or expired. Request another one."
      );
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const updatePassword = db.transaction(() => {
      db.prepare(`
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
      `).run(passwordHash, reset.user_id);

      db.prepare(`
        UPDATE password_resets
        SET used = 1
        WHERE id = ?
      `).run(reset.id);

      db.prepare(`
        UPDATE password_resets
        SET used = 1
        WHERE user_id = ?
      `).run(reset.user_id);
    });

    updatePassword();

    return redirectMessage(
      res,
      "/login",
      "Your password has been updated. You can now log in."
    );
  } catch (error) {
    console.error("Reset-password error:", error.message);

    return redirectMessage(
      res,
      "/forgot-password",
      "We could not reset your password. Please request another reset link."
    );
  }
});

/* =========================================================
   PRIVACY POLICY
========================================================= */

app.get("/privacy", (req, res) => {
  const content = `
    ${pageHeader(
      "Privacy Policy",
      "How this website handles personal information."
    )}

    <section class="section">
      <div class="container">
        <h2>Information We Collect</h2>

        <p>
          Depending on how you use this website, information may include
          your name, email address, account details, messages and support
          pledges you voluntarily submit.
        </p>

        <h2>How Information Is Used</h2>

        <p>
          Information may be used to manage accounts, respond to enquiries,
          record support pledges, maintain website security and communicate
          about requests you make.
        </p>

        <h2>Security and Access</h2>

        <p>
          We take reasonable steps to protect information. No website or
          electronic storage system can be guaranteed completely secure.
          Access to stored information should be restricted to authorized
          people who need it for legitimate purposes.
        </p>

        <h2>Sharing Information</h2>

        <p>
          Personal information should not be sold. Information may need
          to be disclosed where required by law or to address legitimate
          security and operational requirements.
        </p>

        <h2>Your Choices</h2>

        <p>
          For questions or requests concerning information submitted
          through this website, please contact us through the
          <a href="/contact">contact page</a>.
        </p>

        <p class="muted">
          This is a general website privacy notice and should be reviewed
          against the initiative's actual practices and applicable Kenyan
          data protection requirements before publication.
        </p>
      </div>
    </section>
  `;

  res.send(renderPage(req, "Privacy Policy", content));
});

/* =========================================================
   404 PAGE
========================================================= */

app.use((req, res) => {
  res.status(404).send(
    renderPage(
      req,
      "Page Not Found",
      `
        <section class="form-wrap">
          <h1>404 - Page Not Found</h1>
          <p>The requested page could not be found.</p>
          <a class="button" href="/">Return Home</a>
        </section>
      `
    )
  );
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
  console.error("Application error:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).send(
    renderPage(
      req,
      "Server Error",
      `
        <section class="form-wrap">
          <h1>Something Went Wrong</h1>
          <p>Please try again later.</p>
          <a class="button" href="/">Return Home</a>
        </section>
      `
    )
  );
});

/* =========================================================
   START SERVER
========================================================= */

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`Youth Justice Initiative Kenya server listening on port ${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
  console.log(`Database: ${path.join(DATA_DIR, "yjik.sqlite")}`);
});

function shutDown(signal) {
  console.log(`${signal} received. Closing server...`);

  server.close(() => {
    try {
      db.close();
      console.log("Database connection closed.");
      process.exit(0);
    } catch (error) {
      console.error("Shutdown error:", error.message);
      process.exit(1);
    }
  });

  setTimeout(() => process.exit(1), 10000).unref();
}

process.on("SIGTERM", () => shutDown("SIGTERM"));
process.on("SIGINT", () => shutDown("SIGINT"));
