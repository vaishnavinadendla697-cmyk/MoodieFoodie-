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

app.listen(3000, () => console.log("Verification server on :3000"));
