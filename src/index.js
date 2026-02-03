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
import verifyRouter from './api/auth/verify.js'
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
const VerifyRateLimit = rateLimit({
    windowMs: 60*60*1000,
    max: 10,                  
    message: { error: "Too many requests, try again later." },
    standardHeaders: true,    
    legacyHeaders: false,      
});
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:5000",
  "http://localhost:5500",
];

app.use(
  cors({
    origin: function (origin, callback) {
      // allow requests with no origin (like mobile apps or curl)
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) === -1) {
        const msg = `The CORS policy for this site does not allow access from the specified Origin: ${origin}`;
        return callback(new Error(msg), false);
      }
      return callback(null, true);
    },
    credentials: true, // allow cookies to be sent
  })
);
app.use(express.json());
app.use(cookieParser())
app.use(express.static(path.join(__dirname, "../asset")));
app.use(('/api/login'),AuthLimiter,Login)
app.use(('/api/register'),AuthLimiter,Register)
app.use("/verify",VerifyRateLimit, verifyRouter);

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
