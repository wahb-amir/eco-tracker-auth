import User from "../models/User.js";

const OTP_TTL_MS = 60 * 60 * 1000;

export async function cleanupExpiredOtps() {
  const expiryDate = new Date(Date.now() - OTP_TTL_MS);

  const result = await User.updateMany(
    {
      "verificationOtp.createdAt": { $lte: expiryDate }
    },
    {
      $unset: { verificationOtp: "" }
    }
  );

  if (result.modifiedCount > 0) {
    console.log(`🧹 Cleaned ${result.modifiedCount} expired OTPs`);
  }
}
