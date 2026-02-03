import jwt from "jsonwebtoken";
import dotenv from "dotenv"
import path from "path";
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


dotenv.config({ path: path.resolve(__dirname, "../.env") });

const ACCESS_TOKEN = process.env.ACCESS_TOKEN;
const REFRESH_TOKEN = process.env.REFRESH_TOKEN;

const PRIVATE_KEY = process.env.PRIVATE_KEY;
const PUBLIC_KEY = process.env.PUBLIC_KEY;

export const generateAccessToken = (user) => {
  return jwt.sign(user, ACCESS_TOKEN, { expiresIn: "15m" });
};

export const generateRefreshToken = (user) => {
  return (jwt.sign(user, REFRESH_TOKEN), { expiresIn: "7d" });
};

export const verifyAccessToken = (token) => {
  return jwt.verify(token, ACCESS_TOKEN);
};

export const verifyRefreshToken = (token) => {
  return jwt.verify(token, REFRESH_TOKEN);
};

export const generateVerificationToken = (payload, expiresIn = "1h") => {
  return jwt.sign(payload, PRIVATE_KEY, {
    algorithm: "RS256",
    expiresIn,
  });
};

export const verifyVerificationToken = (token) => {
  try {
    const decoded = jwt.verify(token, PUBLIC_KEY, {
      algorithms: ["RS256"],
    });
    return { valid: true, decoded };
  } catch (err) {
    return { valid: false, error: err.message };
  }
};
