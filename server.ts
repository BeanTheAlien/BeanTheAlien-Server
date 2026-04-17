import * as supabase from "@supabase/supabase-js";
import * as bcrypt from "bcrypt";
import cors from "cors";
import cookieParser from "cookie-parser";
import express from "express";
import * as jwt from "jsonwebtoken";
import { config } from "dotenv";
config();

const app = express();
app.use(cors());
app.use(cookieParser());
app.use(express.json());

const client = supabase.createClient(process.env.url as string, process.env.key as string);
const usersTable = client.from("users");

const port = process.env.PORT || 3001;
app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
});