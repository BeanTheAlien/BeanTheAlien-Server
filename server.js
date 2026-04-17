"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const supabase = __importStar(require("@supabase/supabase-js"));
const bcrypt = __importStar(require("bcrypt"));
const cors_1 = __importDefault(require("cors"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const express_1 = __importDefault(require("express"));
const jwt = __importStar(require("jsonwebtoken"));
const dotenv_1 = require("dotenv");
const crypto = __importStar(require("crypto"));
(0, dotenv_1.config)();
const app = (0, express_1.default)();
app.use((0, cors_1.default)());
app.use((0, cookie_parser_1.default)());
app.use(express_1.default.json());
const client = supabase.createClient(process.env.url, process.env.key);
const users = client.from("users");
const secret = "123";
function genToken() {
    return crypto.randomBytes(16).toString("hex");
}
function sign(hex) {
    return jwt.sign({ tk: hex }, secret, { expiresIn: "3d" });
}
async function fltr(username) {
    return (await users.select().filter("username", "eq", username)).data;
}
async function fd(username) {
    return (await fltr(username))?.[0];
}
function verify(tk) {
    return jwt.verify(tk, secret);
}
app.post("/signup", async (req, res) => {
    const { username, password } = req.body;
    if (await fd(username))
        return res.status(400).json({ success: false, message: "A user with this username already exists" });
    const hash = await bcrypt.hash(password, 10);
    const tk = sign(genToken());
    const { error } = await users.insert({ username, password: hash });
    if (error)
        return res.status(500).json({ success: false, message: error.message });
    res.cookie("token", tk, { maxAge: 3 * 24 * 60 * 60 * 1000, httpOnly: true });
    res.status(201).json({ success: true, message: "User created" });
});
app.post("/signin", async (req, res) => {
    const { username, password } = req.body;
    const u = await fd(username);
    if (!u)
        return res.status(400).json({ success: false, message: "No user with this username exists" });
    if (!(await bcrypt.compare(password, u.password)))
        return res.status(400).json({ success: false, message: "Password does not match" });
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
const port = process.env.PORT || 3001;
app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
});
