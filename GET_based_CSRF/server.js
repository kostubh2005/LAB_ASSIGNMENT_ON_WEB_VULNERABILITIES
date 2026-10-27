"use strict";

// Deliberately vulnerable only when the user selects Vulnerable mode.
// This app is for local coursework demonstrations; do not expose it publicly.
const http = require("node:http");
const crypto = require("node:crypto");
const { URL } = require("node:url");

const PORT = Number(process.env.PORT || 3000);
const sessions = new Map();
const html = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

function sessionFor(req, res) {
  const match = (req.headers.cookie || "").match(/(?:^|; )sid=([a-f0-9]+)/);
  let session = match && sessions.get(match[1]);
  if (!session) {
    const id = crypto.randomBytes(24).toString("hex");
    session = { balance: 1000, csrf: crypto.randomBytes(32).toString("hex"), mode: "vulnerable" };
    sessions.set(id, session);
    res.setHeader("Set-Cookie", `sid=${id}; HttpOnly; SameSite=Lax; Path=/`);
  }
  return session;
}

function page(session, message = "") {
  const amount = session.balance;
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>CSRF Variant 1 Lab</title>
  <style>body{font:16px system-ui;max-width:760px;margin:40px auto;padding:0 18px;color:#172033}section{border:1px solid #ccd3df;border-radius:10px;padding:18px;margin:18px 0}.notice{background:#eef5ff;padding:12px;border-radius:6px}.result{color:#075b35;font-weight:bold}button,a{padding:9px 13px;margin:4px;cursor:pointer}code{background:#eef;padding:2px 5px}</style>
  <h1>CSRF Variant 1: GET-based forged action</h1><p class="notice">Local-only training lab. Your simulated account balance is <strong id="balance">$${amount}</strong>.</p>
  <section><h2>1. Set protection mode</h2><p>Current mode: <strong>${html(session.mode)}</strong></p>
  <form method="post" action="/mode"><input type="hidden" name="csrf" value="${session.csrf}"><button name="mode" value="vulnerable">Vulnerable mode</button><button name="mode" value="secure">Secure mode</button></form></section>
  <section><h2>2. Simulated transfer</h2><form method="post" action="/transfer"><input type="hidden" name="csrf" value="${session.csrf}"><label>Amount: $<input name="amount" type="number" min="1" max="500" value="10" required></label><button>Transfer (protected POST)</button></form>
  <p>Vulnerable endpoint: <code>/transfer?amount=10</code> (GET)</p><p><a href="/transfer?amount=10">Try the direct GET payload</a></p></section>
  <section><h2>3. Attacker page</h2><p>Open this page in another tab, then click the button (or wait for the image request).</p><a href="/attacker">Open local attacker page</a></section>
  ${message ? `<p class="result">${html(message)}</p>` : ""}</html>`;
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(body);
}
function readForm(req) {
  return new Promise((resolve) => { let data = ""; req.on("data", (chunk) => { data += chunk; }); req.on("end", () => resolve(new URLSearchParams(data))); });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const session = sessionFor(req, res);
  if (url.pathname === "/") return send(res, 200, page(session));
  if (url.pathname === "/attacker") return send(res, 200, `<!doctype html><meta charset="utf-8"><title>Untrusted attacker page</title><h1>Attacker-controlled page</h1><p>Victim is assumed to be logged in to the simulated site in this same browser.</p><p>Payload: <code>&lt;img src="/transfer?amount=100"&gt;</code></p><button onclick="location.href='/transfer?amount=100'">Trigger forged GET transfer ($100)</button><p>Automatic variant:</p><img src="/transfer?amount=100" alt="" onerror="document.body.insertAdjacentText('beforeend',' Request sent.')"><p><a href="/">Return to account</a></p>`);
  if (url.pathname === "/transfer" && req.method === "GET") {
    if (session.mode === "secure") return send(res, 405, page(session, "Blocked: transfers are not accepted over GET in secure mode."), { Allow: "POST" });
    const amount = Number(url.searchParams.get("amount"));
    if (!Number.isInteger(amount) || amount < 1 || amount > 500) return send(res, 400, page(session, "Invalid transfer amount."));
    session.balance -= amount;
    return send(res, 200, page(session, `VULNERABLE: forged GET accepted; $${amount} transferred. New balance: $${session.balance}.`));
  }
  if (url.pathname === "/mode" && req.method === "POST") {
    const form = await readForm(req);
    if (form.get("csrf") !== session.csrf) return send(res, 403, page(session, "Request rejected: invalid CSRF token."));
    if (["vulnerable", "secure"].includes(form.get("mode"))) session.mode = form.get("mode");
    return send(res, 200, page(session, `Mode changed to ${session.mode}.`));
  }
  if (url.pathname === "/transfer" && req.method === "POST") {
    const form = await readForm(req);
    if (form.get("csrf") !== session.csrf) return send(res, 403, page(session, "Request rejected: invalid CSRF token."));
    const amount = Number(form.get("amount"));
    if (!Number.isInteger(amount) || amount < 1 || amount > 500) return send(res, 400, page(session, "Invalid transfer amount."));
    session.balance -= amount;
    return send(res, 200, page(session, `Protected POST accepted with valid token; $${amount} transferred. New balance: $${session.balance}.`));
  }
  return send(res, 404, page(session, "Not found."));
});

server.listen(PORT, "127.0.0.1", () => console.log(`CSRF Variant 1 lab: http://127.0.0.1:${PORT} (local only)`));
