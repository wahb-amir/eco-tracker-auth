import jwt from "jsonwebtoken";
import dotenv from "dotenv"
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


dotenv.config({ path: path.resolve(__dirname, "../.env") });

const ACCESS_TOKEN = process.env.ACCESS_TOKEN;
const REFRESH_TOKEN = process.env.REFRESH_TOKEN;
const VERIFICATION_TOKEN = process.env.VERIFICATION_TOKEN

export const generateAccessToken = (user) => {
  const token= jwt.sign(user, ACCESS_TOKEN, { expiresIn: "15m" });
  return token;
};

export const generateRefreshToken = (user) => {
   const token= jwt.sign(user, REFRESH_TOKEN, { expiresIn: "7d" });
  return token;
};
export const generateVerificationToken = (user) => {
   const token= jwt.sign(user, VERIFICATION_TOKEN, { expiresIn: "1h" });
  return token;
};

export const verifyVerificationToken = (token) => {
  return jwt.verify(token, VERIFICATION_TOKEN);
};

export function generateOtp(length = 6) {
  return crypto.randomInt(0, 10 ** length)
    .toString()
    .padStart(length, "0");
}

export function hashOtp(otp) {
  return crypto.createHash("sha256").update(otp).digest("hex");
}

export async function setUserOtp(user) {
  const otp = generateOtp(6);
  const otpHash = hashOtp(otp);

  user.verificationOtp = {
    codeHash: otpHash,
    createdAt: new Date(),
  };

  await user.save();

  return otp; 
}

export const verifyAccessToken = (token) => {
  return jwt.verify(token, ACCESS_TOKEN);
};


export const verifyRefreshToken = (token) => {
  return jwt.verify(token, REFRESH_TOKEN);
};


