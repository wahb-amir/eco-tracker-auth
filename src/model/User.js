// models/User.js
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const OTP_TTL_MS = 60 * 60 * 1000; // 60 minutes
const OTP_LENGTH = 6;

const verificationOtpSchema = new mongoose.Schema(
  {
    codeHash: { type: String, default: null }, // hashed OTP
    createdAt: { type: Date, default: null },
  },
  { _id: false }
);

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  verified: { type: Boolean, default: false },

  verificationOtp: {
    type: verificationOtpSchema,
    default: () => ({})
  },
});

// ----------------- password hashing -----------------
userSchema.pre("save", async function (next) {
  try {
    if (!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password, 10);
    return next();
  } catch (err) {
    return next(err);
  }
});

// compare password
userSchema.methods.isValidPassword = async function (password) {
  return bcrypt.compare(password, this.password);
};

// ----------------- OTP helpers -----------------
function generateNumericOtp(length = OTP_LENGTH) {
  const min = 10 ** (length - 1);
  const max = 10 ** length - 1;
  return String(Math.floor(Math.random() * (max - min + 1)) + min);
}

function hashOtp(otp) {
  return crypto.createHash("sha256").update(String(otp)).digest("hex");
}

/**
 * Generate & store a new OTP (hashed). Returns the plain OTP (caller should email/sms it).
 * options: { length: number }
 */
userSchema.methods.setVerificationOtp = async function (options = {}) {
  const length = options.length || OTP_LENGTH;
  const otp = generateNumericOtp(length);
  const codeHash = hashOtp(otp);

  this.verificationOtp = {
    codeHash,
    createdAt: new Date(),
  };

  await this.save();
  return otp; 
};

userSchema.methods.verifyOtp = async function (candidateOtp) {
  if (!this.verificationOtp || !this.verificationOtp.createdAt || !this.verificationOtp.codeHash) {
    return { ok: false, reason: "no_otp" };
  }

  const createdAt = new Date(this.verificationOtp.createdAt);
  const now = Date.now();

  // check expiry in code (do not rely solely on TTL index)
  if (now - createdAt.getTime() > OTP_TTL_MS) {
    // clear OTP
    this.verificationOtp = { codeHash: null, createdAt: null };
    await this.save();
    return { ok: false, reason: "expired" };
  }

  const candidateHash = hashOtp(candidateOtp);
  if (candidateHash !== this.verificationOtp.codeHash) {
    return { ok: false, reason: "invalid" };
  }

  // success: mark verified and clear OTP
  this.verified = true;
  this.verificationOtp = { codeHash: null, createdAt: null };
  await this.save();

  return { ok: true };
};


userSchema.methods.clearOtp = async function () {
  this.verificationOtp = { codeHash: null, createdAt: null };
  await this.save();
};

// ----------------- export model safely (avoids overwrite in dev/hot reload) -----------------
const UserModel = mongoose.models.User || mongoose.model("User", userSchema);
export default UserModel;
