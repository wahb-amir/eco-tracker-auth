import jwt from "jsonwebtoken";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

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

export const generateVerificationToken = (userId) => {
  return jwt.sign(
    { uid: userId },
    VERIFICATION_TOKEN_SECRET,
    { expiresIn: "1h" }
  );
};

export const verifyAccessToken = (token) =>
  jwt.verify(token, ACCESS_TOKEN_SECRET);

export const verifyRefreshToken = (token) =>
  jwt.verify(token, REFRESH_TOKEN_SECRET);

export const verifyVerificationToken = (token) =>
  jwt.verify(token, VERIFICATION_TOKEN_SECRET);

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

export async function setUserOtp(user, ttlMinutes = 60) {
  const otp = generateOtp();
  const otpHash = hashOtp(otp);

  user.verificationOtp = {
    codeHash: otpHash,
    expiresAt: new Date(Date.now() + ttlMinutes * 60 * 1000),
  };

  await user.save();
  return otp;
}

export function verifyOtp(user, otp) {
  if (!user.verificationOtp) return false;

  const { codeHash, expiresAt } = user.verificationOtp;
  if (Date.now() > expiresAt.getTime()) return false;

  return hashOtp(otp) === codeHash;
}
