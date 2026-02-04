import mongoose from "mongoose";
import crypto from "crypto";

const OTP_TTL_SECONDS = 60 * 60; // 1 hour
const OTP_LENGTH = 6;


/**
 Generate numeric OTP
*/
export function generateNumericOtp(length = OTP_LENGTH) {
  const min = 10 ** (length - 1);
  const max = 10 ** length - 1;

  return String(
    Math.floor(Math.random() * (max - min + 1)) + min
  );
}


/**
 Hash OTP (never store plaintext)
*/
export function hashOtp(otp) {
  return crypto
    .createHash("sha256")
    .update(String(otp))
    .digest("hex");
}


const otpSchema = new mongoose.Schema({
  
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    unique: true, // ensures one OTP per user
    index: true,
  },

  codeHash: {
    type: String,
    required: true,
  },

  createdAt: {
    type: Date,
    default: Date.now,
    expires: OTP_TTL_SECONDS, // 🔥 AUTO DELETE
  },

}, {
  timestamps: false
});


// ⚡ optional compound index (great for very large apps)
otpSchema.index({ userId: 1, createdAt: -1 });


// ---------------- STATIC METHODS ----------------

/**
 Create or replace OTP
*/
otpSchema.statics.createForUser = async function(userId) {

  const otp = generateNumericOtp();
  const codeHash = hashOtp(otp);

  await this.findOneAndUpdate(
    { userId },
    {
      codeHash,
      createdAt: new Date(),
    },
    {
      upsert: true,
      new: true,
      setDefaultsOnInsert: true,
    }
  );

  return otp; // send via email
};


/**
 Verify OTP
*/
otpSchema.statics.verifyForUser = async function(userId, candidateOtp) {

  const record = await this.findOne({ userId });

  if (!record) {
    return { ok: false, reason: "no_otp" };
  }

  const candidateHash = hashOtp(candidateOtp);

  if (candidateHash !== record.codeHash) {
    return { ok: false, reason: "invalid" };
  }

  // delete immediately after success
  await this.deleteOne({ _id: record._id });

  return { ok: true };
};


const OtpModel =
  mongoose.models.Otp ||
  mongoose.model("Otp", otpSchema);

export default OtpModel;
