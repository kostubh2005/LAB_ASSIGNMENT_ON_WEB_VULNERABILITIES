const express = require("express");
const fs      = require("fs");
const path    = require("path");
const app     = express();

// ── Helper to load HTML templates ──
const load = (name) => fs.readFileSync(path.join(__dirname, "views", name), "utf8");

// ── Serve static files (style.css) ──
app.use(express.static(__dirname));

// ── HTML-escape helper (the mitigation) ──
function escapeHtml(str) {
  return String(str)
    .replace(/&/g,  "&amp;")
    .replace(/</g,  "&lt;")
    .replace(/>/g,  "&gt;")
    .replace(/"/g,  "&quot;")
    
    .replace(/'/g,  "&#39;");
}

// ── Routes ──

// Home
app.get("/", (_req, res) => {
  res.cookie("session_id", "user_abc123_secret_token", { httpOnly: false });
  res.send(load("index.html"));
});

// (a) VULNERABLE — user input placed directly into HTML, no encoding
app.get("/vulnerable", (req, res) => {
  res.cookie("session_id", "user_abc123_secret_token", { httpOnly: false });
  const q = req.query.q;
  const page = load("vulnerable.html");

  if (q === undefined) {
    res.send(page.replace("{{RESULT}}", ""));
  } else {
    const resultHtml = `
      <div class="result-box result-vuln">
        <span class="result-label">Server response (raw HTML):</span>
        <div class="result-body">You searched for: ${q}</div>
      </div>`;                          // ← FLAW: q inserted without encoding
    res.send(page.replace("{{RESULT}}", resultHtml));
  }
});

// (d) MITIGATED — HTML-encode input before rendering
app.get("/safe", (req, res) => {
  res.cookie("session_id", "user_abc123_secret_token", { httpOnly: false });
  const q = req.query.q;
  const page = load("safe.html");

  if (q === undefined) {
    res.send(page.replace("{{RESULT}}", ""));
  } else {
    const resultHtml = `
      <div class="result-box result-safe">
        <span class="result-label">Server response (encoded):</span>
        <div class="result-body">You searched for: ${escapeHtml(q)}</div>
      </div>`;                          // ← FIX: q is escaped first
    res.send(page.replace("{{RESULT}}", resultHtml));
  }
});

// ── Start ──
app.listen(3000, "127.0.0.1", () =>
  console.log("Running at http://127.0.0.1:3000")
);