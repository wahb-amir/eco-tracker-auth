// models/User.js
import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  verified: { type: Boolean, default: false },

  verificationToken: {
    token: { type: String, default: null },
    createdAt: { type: Date, default: null, expires: 3600 }, // 1 hour expiry
  },
});

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Compare password
userSchema.methods.isValidPassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// Set verification token
userSchema.methods.setVerificationToken = function (token) {
  this.verificationToken = {
    token,
    createdAt: new Date(),
  };
};


userSchema.methods.isVerificationTokenValid = function (token) {
  if (!this.verificationToken?.token) return false;
  return this.verificationToken.token === token;
};

// Mark user as verified
userSchema.methods.markVerified = function () {
  this.verified = true;
  this.verificationToken = { token: null, createdAt: null }; // clear token
};

export default mongoose.model("User", userSchema);
