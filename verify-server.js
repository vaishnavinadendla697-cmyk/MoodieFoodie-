// Minimal UTR verification server (Node 18+, `npm i express`).
// The browser can NOT verify a UTR by itself. Only a server that receives real
// payment data (from your payment gateway webhook or bank API) can.
//
// Flow:
//  1. Customer pays; the UPI link carries a unique order id in `tr`/`tn`.
//  2. Your gateway/bank calls POST /webhook with the credited payment (utr, amount, order, time).
//  3. Website calls POST /verify with the UTR the user typed + the order id.
//  4. Premium is granted only if a REAL payment exists with that UTR, the same order id,
//     the right amount, made after this payment session began, and never used before.

const express = require("express");
const app = express();
app.use(express.json());
app.use((req, res, next) => { res.set("Access-Control-Allow-Origin", "*"); res.set("Access-Control-Allow-Headers", "Content-Type"); if (req.method === "OPTIONS") return res.sendStatus(204); next(); });

const AMOUNT = 59;
const payments = new Map(); // utr -> { utr, amount, order, paidAt, claimedBy }
// TODO: use a real database (with a UNIQUE constraint on utr) in production.

// TODO: verify the gateway's signature header here (Razorpay/Cashfree/PhonePe all provide one).
app.post("/webhook", (req, res) => {
  const { utr, amount, order, paidAt } = req.body;
  payments.set(String(utr), { utr: String(utr), amount: Number(amount), order, paidAt: paidAt || Date.now(), claimedBy: null });
  res.sendStatus(200);
});

app.post("/verify", (req, res) => {
  const { utr, order, amount, startedAt, user } = req.body || {};
  const p = payments.get(String(utr));
  const no = reason => res.json({ verified: false, reason });

  if (!p) return res.json({ verified: false, pending: true }); // not received yet: bank may be slow
  if (p.claimedBy) return no("This UTR has already been used.");
  if (p.order !== order) return no("This UTR belongs to a different payment.");
  if (p.amount !== AMOUNT || Number(amount) !== AMOUNT) return no("Payment amount does not match.");
  if (p.paidAt < Number(startedAt) - 60 * 1000) return no("This payment was made before this checkout started.");

  p.claimedBy = user; // one-time use, atomic in a real DB
  res.json({ verified: true, until: Date.now() + 30 * 864e5 });
});


// ---------------------------------------------------------------------------
// OTP by SMS (mobile number) or email (signup verification + forgot password)
//  POST /otp/send   { to: "<10-digit mobile or email>", purpose: "signup" | "reset" }
//  POST /otp/verify { to, purpose, code }  ->  { verified: true }
// SMS:   set TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM  (India: MSG91/Fast2SMS need DLT registration)
// Email: npm i nodemailer, then set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM
//        (Gmail: smtp.gmail.com, port 465, user = your Gmail, pass = an App Password)
// Without these (and NODE_ENV != production) the OTP is printed in this console.
// Production: keep `otps` in Redis/DB, and add per-IP rate limiting.
// ---------------------------------------------------------------------------
const crypto = require("crypto");
let nodemailer = null; try { nodemailer = require("nodemailer"); } catch (e) {}
const OTP_TTL = 5 * 60 * 1000, RESEND_MS = 30 * 1000, MAX_TRIES = 5, MAX_SENDS_PER_HOUR = 5;
const OTP_SECRET = process.env.OTP_SECRET || crypto.randomBytes(32).toString("hex");
const otps = new Map(); // "purpose:to" -> { hash, exp, tries, sends: [timestamps] }
const hashOtp = (to, code) => crypto.createHmac("sha256", OTP_SECRET).update(to + ":" + code).digest("hex");

const isEmail = t => /^\S+@\S+\.\S+$/.test(t) && t.length <= 254;
const isPhone = t => /^[6-9]\d{9}$/.test(t);
const okPurpose = p => p === "signup" || p === "reset";
const normalize = t => String(t || "").trim().toLowerCase();

async function sendSms(phone, text) {
  const { TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM } = process.env;
  if (TWILIO_SID && TWILIO_TOKEN && TWILIO_FROM) {
    const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${TWILIO_SID}/Messages.json`, {
      method: "POST",
      headers: { Authorization: "Basic " + Buffer.from(`${TWILIO_SID}:${TWILIO_TOKEN}`).toString("base64"), "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ To: "+91" + phone, From: TWILIO_FROM, Body: text })
    });
    if (!r.ok) throw new Error("SMS provider error " + r.status);
    return;
  }
  if (process.env.NODE_ENV === "production") throw new Error("No SMS provider configured");
  console.log(`[DEV SMS to +91${phone}] ${text}`);
}

async function sendEmail(to, text) {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM } = process.env;
  if (nodemailer && SMTP_HOST && SMTP_USER && SMTP_PASS) {
    const port = Number(SMTP_PORT || 465);
    const tx = nodemailer.createTransport({ host: SMTP_HOST, port, secure: port === 465, auth: { user: SMTP_USER, pass: SMTP_PASS } });
    await tx.sendMail({ from: MAIL_FROM || SMTP_USER, to, subject: "Your MoodieFoodie OTP", text });
    return;
  }
  if (process.env.NODE_ENV === "production") throw new Error("No email provider configured");
  console.log(`[DEV EMAIL to ${to}] ${text}`);
}

app.post("/otp/send", async (req, res) => {
  const to = normalize(req.body && (req.body.to || req.body.phone)), purpose = req.body && req.body.purpose;
  if (!(isEmail(to) || isPhone(to)) || !okPurpose(purpose)) return res.status(400).json({ error: "Enter a valid email address or 10-digit mobile number." });
  const key = purpose + ":" + to, now = Date.now();
  const rec = otps.get(key) || { sends: [], tries: 0 };
  rec.sends = rec.sends.filter(t => now - t < 3600e3);
  const last = rec.sends[rec.sends.length - 1];
  if (last && now - last < RESEND_MS) return res.status(429).json({ error: `Please wait ${Math.ceil((RESEND_MS - (now - last)) / 1000)}s before requesting another OTP.` });
  if (rec.sends.length >= MAX_SENDS_PER_HOUR) return res.status(429).json({ error: "Too many OTP requests. Please try again in an hour." });
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  const text = `${code} is your MoodieFoodie OTP. It is valid for 5 minutes. Do not share it with anyone.`;
  try { await (isEmail(to) ? sendEmail(to, text) : sendSms(to, text)); }
  catch (e) { console.error(e.message); return res.status(502).json({ error: isEmail(to) ? "Could not send the email. Please try again." : "Could not send the SMS. Please try again." }); }
  rec.sends.push(now); rec.hash = hashOtp(to, code); rec.exp = now + OTP_TTL; rec.tries = 0;
  otps.set(key, rec);
  res.json({ sent: true });
});

app.post("/otp/verify", (req, res) => {
  const to = normalize(req.body && (req.body.to || req.body.phone)), { purpose, code } = req.body || {};
  if (!(isEmail(to) || isPhone(to)) || !okPurpose(purpose) || !/^\d{6}$/.test(String(code))) return res.status(400).json({ error: "Enter the 6-digit OTP." });
  const key = purpose + ":" + to, rec = otps.get(key);
  if (!rec || !rec.hash) return res.status(400).json({ error: "Please request an OTP first." });
  if (Date.now() > rec.exp) { otps.delete(key); return res.status(400).json({ error: "This OTP has expired. Please request a new one." }); }
  if (++rec.tries > MAX_TRIES) { otps.delete(key); return res.status(429).json({ error: "Too many wrong attempts. Please request a new OTP." }); }
  const x = Buffer.from(rec.hash), y = Buffer.from(hashOtp(to, String(code)));
  if (x.length !== y.length || !crypto.timingSafeEqual(x, y)) return res.status(400).json({ error: "Incorrect OTP. Please try again." });
  otps.delete(key); // one-time use
  res.json({ verified: true });
});

app.listen(3000, () => console.log("Verification server on :3000"));

