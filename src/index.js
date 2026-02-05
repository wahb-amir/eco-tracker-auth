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
import verifyRouter from './api/auth/verify/verify.js'
import meRouter from "./api/auth/user/me.js";
import cron from "node-cron";
import { cleanupExpiredOtps } from "./utils/otpCleanup.js";
import chalk from 'chalk'; // Optional: npm install chalk for colors


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
  "http://localhost:9002",
];
cron.schedule("*/10 * * * *", cleanupExpiredOtps);
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) === -1) {
        const msg = `The CORS policy for this site does not allow access from the specified Origin: ${origin}`;
        return callback(new Error(msg), false);
      }
      return callback(null, true);
    },
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser())
const advancedLogger = (req, res, next) => {
  const start = Date.now();
  const timestamp = new Date().toISOString();
  
  // 1. Capture Request Details immediately (especially for Preflights)
  const { method, originalUrl, ip } = req;
  const userAgent = req.get('User-Agent') || 'unknown';

  // 2. Track when the response is sent back to the client
  res.on('finish', () => {
    const duration = Date.now() - start;
    const { statusCode } = res;
    
    // Colorize status code for readability
    let statusColor = chalk.green;
    if (statusCode >= 400) statusColor = chalk.yellow;
    if (statusCode >= 500) statusColor = chalk.red;
    if (method === 'OPTIONS') statusColor = chalk.cyan;

    const logEntry = {
      timestamp,
      method: chalk.bold(method),
      url: originalUrl,
      status: statusColor(statusCode),
      duration: `${duration}ms`,
      ip,
      // Useful for debugging CORS/Auth issues
      origin: req.get('origin') || 'no-origin',
      cookiePresent: !!req.get('cookie'),
    };

    console.log(
      `[${logEntry.timestamp}] ${logEntry.method} ${logEntry.url} ` +
      `${logEntry.status} - ${logEntry.duration} | Origin: ${logEntry.origin} | Cookie: ${logEntry.cookiePresent}`
    );

    // If it's a preflight or a failure, log extra headers for debugging
    if (method === 'OPTIONS' || statusCode >= 400) {
      console.log(chalk.gray(`   > UA: ${userAgent}`));
      console.log(chalk.gray(`   > Auth Header: ${!!req.get('authorization')}`));
    }
  });

  next();
};


app.use(advancedLogger);
app.use(express.static(path.join(__dirname, "../asset")));
app.use(('/api/auth/login'),AuthLimiter,Login)
app.use(('/api/auth/register'),AuthLimiter,Register)
app.use("/api/auth/verify",VerifyRateLimit, verifyRouter);
app.use("/api/user", meRouter);
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
