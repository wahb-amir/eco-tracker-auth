// models/Otp.js
import mongoose from "mongoose";
import crypto from "crypto";

const OTP_TTL_SECONDS = 60 * 60; // 1 hour
const OTP_LENGTH = 6;

/**
 * Generate numeric OTP (cryptographically acceptable entropy for 6 digits).
 * If you want stronger entropy, replace with crypto.randomInt.
 */
export function generateNumericOtp(length = OTP_LENGTH) {
  const min = 10 ** (length - 1);
  const max = 10 ** length - 1;
  return String(Math.floor(Math.random() * (max - min + 1)) + min);
}

/**
 * Hash OTP (never store plaintext).
 * Uses SHA-256 to compare server-side.
 */
export function hashOtp(otp) {
  return crypto.createHash("sha256").update(String(otp)).digest("hex");
}

const otpSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    // purpose of OTP: email verification, password reset, etc.
    type: {
      type: String,
      enum: ["email_verification", "password_reset"],
      default: "email_verification",
      required: true,
    },

    codeHash: {
      type: String,
      required: true,
    },

    // explicit expiry time so TTL can be precise and per-type durations are possible
    expiresAt: {
      type: Date,
      required: true,
      default: () => new Date(Date.now() + OTP_TTL_SECONDS * 1000),
    },

    // optional: track attempts to throttle brute force (can be used later)
    attempts: {
      type: Number,
      default: 0,
      required: true,
    },
  },
  {
    timestamps: false,
  }
);

// Ensure one active OTP per user+type (prevents races / duplicates)
otpSchema.index({ userId: 1, type: 1 }, { unique: true });

// TTL index: Mongo will delete OTP documents when expiresAt <= now
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// ---------------- STATIC METHODS ----------------

/**
 * Create or replace OTP for userId + type.
 * Returns the plaintext OTP (caller must send it via email/SMS).
 */
otpSchema.statics.createForUser = async function (userId, type = "email_verification", options = {}) {
  const length = options.length || OTP_LENGTH;
  const otp = generateNumericOtp(length);
  const codeHash = hashOtp(otp);
  const expiresAt = options.expiresAt ?? new Date(Date.now() + (options.ttlSeconds ?? OTP_TTL_SECONDS) * 1000);

  await this.findOneAndUpdate(
    { userId, type },
    { codeHash, expiresAt, attempts: 0 },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );

  return otp;
};

/**
 * Verify OTP for userId + type.
 * Returns { ok: true } on success (and deletes OTP doc),
 * or { ok: false, reason } where reason is "no_otp" | "expired" | "invalid" | "too_many_attempts".
 */
otpSchema.statics.verifyForUser = async function (userId, candidateOtp, type = "email_verification", options = {}) {
  const maxAttempts = options.maxAttempts ?? 10;

  const record = await this.findOne({ userId, type });
  if (!record) return { ok: false, reason: "no_otp" };

  // check expiry explicitly (TTL may not have removed it yet)
  if (record.expiresAt && record.expiresAt.getTime() <= Date.now()) {
    await this.deleteOne({ _id: record._id });
    return { ok: false, reason: "expired" };
  }

  // enforce attempts limit
  if (record.attempts >= maxAttempts) {
    await this.deleteOne({ _id: record._id });
    return { ok: false, reason: "too_many_attempts" };
  }

  const candidateHash = hashOtp(candidateOtp);
  if (candidateHash !== record.codeHash) {
    // increment attempts
    await this.updateOne({ _id: record._id }, { $inc: { attempts: 1 } });
    return { ok: false, reason: "invalid" };
  }

  // success: delete OTP record (one-time use)
  await this.deleteOne({ _id: record._id });
  return { ok: true };
};

/**
 * Clear OTPs for a user (by type optional)
 */
otpSchema.statics.clearForUser = async function (userId, type = null) {
  const q = { userId };
  if (type) q.type = type;
  await this.deleteMany(q);
};

const OtpModel = mongoose.models.Otp || mongoose.model("Otp", otpSchema);
export default OtpModel;
