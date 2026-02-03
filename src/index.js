import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import connectWithRetry from "./utils/db.js";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import Login from "./api/auth/login.js"
import Register from "./api/auth/register.js"

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.resolve(__dirname, ".env") });

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

const app = express();
const AuthLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 8,                  
    message: { error: "Too many requests, try again later." },
    standardHeaders: true,    
    legacyHeaders: false,      
});
app.use(cors());
app.use(express.json());
app.use(cookieParser())
app.use(express.static(path.join(__dirname, "../asset")));
app.use(('/api/login'),AuthLimiter,Login)
app.use(('/api/register'),AuthLimiter,Register)

app.get("/", (req, res) => {
  res.json({ msg: "hello" });
});


const startServer = async () => {
  await connectWithRetry(MONGO_URI); 
  app.listen(PORT, () => {
    console.log(`Server running at Port: ${PORT}`);
  });
};

startServer();
