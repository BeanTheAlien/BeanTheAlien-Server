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
app.use(cors());
app.use(cookieParser());
app.use(express.json());

const client = supabase.createClient(process.env.url as string, process.env.key as string);
const users = client.from("users");
const secret = "123";

function genToken() { return crypto.randomBytes(16).toString("hex"); }
function sign(hex: string) { return jwt.sign({ tk: hex }, secret, { expiresIn: "3d" }); }
app.post("signup", async (req, res) => {
    const { username, password } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const tk = sign(genToken());
    const { error } = await users.insert({ username, password: hash });
    if(error) return res.status(401).json({ success: false, message: error.message });
    res.cookie("token", tk, { maxAge: 3 * 24 * 60 * 60 * 1000, httpOnly: true });
});
app.post("signin", async (req, res) => {
    const { username, password } = req.body;
    const tk = sign(genToken());
    res.cookie("token", tk, { maxAge: 3 * 24 * 60 * 60 * 1000, httpOnly: true });
});

const port = process.env.PORT || 3001;
app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
});