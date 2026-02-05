import jwt from "jsonwebtoken";
import crypto from "crypto";
import dotenv from "dotenv";
import path from "path"
import { fileURLToPath } from "url";
import { decode } from "punycode";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.resolve(__dirname, "../.env") });

const {
  ACCESS_TOKEN_SECRET,
  REFRESH_TOKEN_SECRET,
  VERIFICATION_TOKEN_SECRET,
} = process.env;

if (!ACCESS_TOKEN_SECRET || !REFRESH_TOKEN_SECRET || !VERIFICATION_TOKEN_SECRET) {
  console.error("❌ JWT secrets missing in .env");
  process.exit(1);
}

/* ───────────────── JWT HELPERS ───────────────── */

export const generateAccessToken = (userId) => {
  return jwt.sign(
    { uid: userId },
    ACCESS_TOKEN_SECRET,
    { expiresIn: "15m" }
  );
};

export const generateRefreshToken = (userId) => {
  return jwt.sign(
    { uid: userId },
    REFRESH_TOKEN_SECRET,
    { expiresIn: "7d" }
  );
};

export const generateVerificationToken = (payload) => {
  return jwt.sign(
    payload,
    VERIFICATION_TOKEN_SECRET,
    { expiresIn: "1h" }
  );
};

export const verifyAccessToken = (token) =>{
  const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
  return decoded
}

export const verifyRefreshToken = (token) =>{
  const decoded = jwt.verify(token, REFRESH_TOKEN_SECRET);
  return decoded
}

export const verifyVerificationToken = (token) =>{
  const decoded = jwt.verify(token, VERIFICATION_TOKEN_SECRET);
  return decoded
}

/* ───────────────── OTP HELPERS ───────────────── */

export function generateOtp(length = 6) {
  return crypto
    .randomInt(0, 10 ** length)
    .toString()
    .padStart(length, "0");
}

export function hashOtp(otp) {
  return crypto
    .createHash("sha256")
    .update(otp)
    .digest("hex");
}


export function verifyOtp(user, otp) {
  if (!user.verificationOtp) return false;

  const { codeHash, expiresAt } = user.verificationOtp;
  if (Date.now() > expiresAt.getTime()) return false;

  return hashOtp(otp) === codeHash;
}

/* ───────────────── ROTATE TOKENS ───────────────── */

export async function rotateTokens(refreshToken) {
  if (!refreshToken) return null;

  try {

    const decoded = verifyRefreshToken(refreshToken); 
    const userId = decoded.uid;
    const user = { id: userId }; 

    const newAccessToken = generateAccessToken(userId);
    const newRefreshToken = generateRefreshToken(userId);

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      user,
    };
  } catch (err) {

    return null;
  }
}
