// models/User.js
import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },

  // Verification token
  verificationToken: {
    token: { type: String, default: null },
    createdAt: { type: Date, default: null, expires: 3600 } // 3600 sec = 60 min
  }
});

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.isValidPassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.setVerificationToken = function (token) {
  this.verificationToken = {
    token,
    createdAt: new Date()
  };
};

userSchema.methods.isVerificationTokenValid = function (token) {
  if (!this.verificationToken?.token) return false;
  return this.verificationToken.token === token;
};

export default mongoose.model("User", userSchema);
