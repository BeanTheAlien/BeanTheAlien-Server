import * as supabase from "@supabase/supabase-js";
import * as bcrypt from "bcrypt";
import cors from "cors";
import cookieParser from "cookie-parser";
import express from "express";
import * as jwt from "jsonwebtoken";
import { config } from "dotenv";
import * as crypto from "crypto";
import * as nodemailer from "nodemailer";
import type { CookieOptions, Request, Response } from "express";
config();

const app = express();
app.use(cors({
    origin: ["https://beanthealien.github.io", "http://127.0.0.1:5500"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(cookieParser());
app.use(express.json());

const client = supabase.createClient(process.env.url as string, process.env.key as string);
const users = client.from("users");
const pfps = client.from("pfp");
const secret = "123";
const transport = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "ben.allen.goldstein@gmail.com",
        pass: process.env.mail
    }
});
const isProd = process.env.NODE_ENV === "production";
console.log(process.env.NODE_ENV);

function genToken() {
    return crypto.randomBytes(16).toString("hex");
}
function sign(hex: string) {
    return jwt.sign({ tk: hex }, secret, { expiresIn: "3d" });
}
async function fltr(username: string) {
    return (await users.select().filter("username", "eq", username)).data;
}
async function fltrPfps(username: string) {
    return (await pfps.select().filter("username", "eq", username)).data;
}
async function fd(username: string) {
    return (await fltr(username))?.[0];
}
async function fdPfps(username: string) {
    return (await fltrPfps(username))?.[0];
}
function verify(tk: string) {
    return jwt.verify(tk, secret);
}
function sendEmail(from: string, to: string, subject: string, html: string) {
    transport.sendMail({ from, to, subject, html });
}
function getToken(req: Request) {
    return req.cookies.token;
}
function getUsername(req: Request) {
    return req.cookies.username;
}
function cookies(res: Response, token: string, username: string) {
    const opts: CookieOptions = { maxAge: 3 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: isProd ? "none" : "lax", secure: isProd };
    res.cookie("token", token, opts);
    res.cookie("username", username, opts);
}

app.post("/signup", async (req, res) => {
    const { username, email, password, promotions } = req.body;
    if(await fd(username)) return res.status(400).json({ success: false, message: "A user with this username already exists" });
    const hash = await bcrypt.hash(password, 10);
    const tk = sign(genToken());
    const { error } = await users.insert({ username, email, password: hash, promotions });
    if(error) return res.status(500).json({ success: false, message: error.message });
    cookies(res, tk, username);
    res.status(201).json({ success: true, message: "User created" });
});
app.post("/signin", async (req, res) => {
    const { username, password } = req.body;
    const u = await fd(username);
    if(!u) return res.status(400).json({ success: false, message: "No user with this username exists" });
    if(!(await bcrypt.compare(password, u.password))) return res.status(400).json({ success: false, message: "Password does not match" });
    const tk = sign(genToken());
    cookies(res, tk, username);
    res.json({ success: true, message: "Logged in successfully" });
});
app.post("/verify", async (req, res) => {
    const t = getToken(req);
    res.send({ r: t && verify(t) });
});
app.post("/verifytk", async (req, res) => {
    res.send({ r: verify(req.body.token) });
});
app.get("/wakeup");
app.post("/user", async (req, res) => {
    res.send({ u: await fd(getUsername(req)) });
});
app.post("/sendemail", async (req, res) => {
    const { from, to, subject, html } = req.body;
    sendEmail(from, to, subject, html);
});
app.post("/getpfp", async (req, res) => {
    res.send({ pfp: await fdPfps(getUsername(req)) });
});
app.post("/setpfp", async (req, res) => {
    const { bytes } = req.body;
    const u = getUsername(req);
    const { error } = await pfps.upsert({ username: u, pfp: bytes }).eq("username", u);
    if(error) return res.status(500).json({ success: false, message: error.message });
    res.json({ success: true });
});
app.get("/cookies", async (req, res) => {
    res.send({ c: [getToken(req), getUsername(req)] });
});

const port = process.env.PORT || 3001;
app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
});