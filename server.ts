import * as supabase from "@supabase/supabase-js";
import * as bcrypt from "bcrypt";
import cors from "cors";
import cookieParser from "cookie-parser";
import express from "express";
import * as jwt from "jsonwebtoken";
import { config } from "dotenv";
import * as crypto from "crypto";
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
const secret = "123";

function genToken() {
    return crypto.randomBytes(16).toString("hex");
}
function sign(hex: string) {
    return jwt.sign({ tk: hex }, secret, { expiresIn: "3d" });
}
async function fltr(username: string) {
    return (await users.select().filter("username", "eq", username)).data;
}
async function fd(username: string) {
    return (await fltr(username))?.[0];
}
function verify(tk: string) {
    return jwt.verify(tk, secret);
}

app.post("/signup", async (req, res) => {
    const { username, password } = req.body;
    if(await fd(username)) return res.status(400).json({ success: false, message: "A user with this username already exists" });
    const hash = await bcrypt.hash(password, 10);
    const tk = sign(genToken());
    const { error } = await users.insert({ username, password: hash });
    if(error) return res.status(500).json({ success: false, message: error.message });
    res.cookie("token", tk, { maxAge: 3 * 24 * 60 * 60 * 1000, httpOnly: true });
    res.status(201).json({ success: true, message: "User created" });
});
app.post("/signin", async (req, res) => {
    const { username, password } = req.body;
    const u = await fd(username);
    if(!u) return res.status(400).json({ success: false, message: "No user with this username exists" });
    if(!(await bcrypt.compare(password, u.password))) return res.status(400).json({ success: false, message: "Password does not match" });
    const tk = sign(genToken());
    res.cookie("token", tk, { maxAge: 3 * 24 * 60 * 60 * 1000, httpOnly: true });
    res.json({ success: true, message: "Logged in successfully" });
});
app.post("/verify", async (req, res) => {
    res.send({ r: verify(req.cookies.token) });
});
app.post("/verifytk", async (req, res) => {
    res.send({ r: verify(req.body.token) });
});
app.get("/wakeup");
app.post("/user", async (req, res) => {
    const { username } = req.body;
    res.send({ u: await fd(username) });
});

const port = process.env.PORT || 3001;
app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
});