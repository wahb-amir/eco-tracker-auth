import express from "express";
import mongoose from "mongoose";
import User from "../../model/User.js";
import Otp from "../../model/Otp.js";
import {
  generateVerificationToken,
  generateOtp,
  hashOtp,
} from "../../utils/token.js";
import { sendOtpEmail } from "../../utils/mailer.js";
import { hashPassword } from "../../utils/hashPassword.js";

const router = express.Router();

router.post("/", async (req, res) => {
  const session = await mongoose.startSession();

  try {
    session.startTransaction();

    let { email, password, name } = req.body;

    // ---------- validation ----------
    if (!email || !password || !name) {
      return res.status(400).json({ msg: "All fields are required" });
    }

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      typeof name !== "string"
    ) {
      return res.status(400).json({ msg: "Credentials must be strings" });
    }

    email = email.trim().toLowerCase();
    name = name.trim();

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ msg: "Invalid email address" });
    }

    if (password.length < 8) {
      return res
        .status(400)
        .json({ msg: "Password must be at least 8 characters" });
    }

    // ---------- check existing ----------
    const existing = await User.findOne({ email }).session(session);
    if (existing) {
      return res
        .status(409)
        .json({ msg: "User with this email already exists" });
    }

    const hashedPassword = await hashPassword(password);

    // ---------- create user ----------
    const userDoc = await User.create(
      [{ name, email, password: hashedPassword }],
      { session }
    );

    const user = userDoc[0];

    
    const otp = generateOtp(6);

    await Otp.deleteMany({ userId: user._id }).session(session);

    await Otp.create(
      [
        {
          userId: user._id,
          codeHash: hashOtp(otp),
        },
      ],
      { session }
    );

    // ---------- commit BEFORE email ----------
    await session.commitTransaction();
    session.endSession();

    // ---------- verification cookie ----------
    const verificationToken = generateVerificationToken({
      uid: user._id.toString(),
      email: user.email,
    });

    res.cookie("verificationToken", verificationToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 60 * 60 * 1000,
      path: "/",
    });


    try {
      await sendOtpEmail(email, otp, { expiryMinutes: 60 });
    } catch (mailErr) {
      console.error("Email failed, rolling back user + otp");

      await Promise.all([
        User.deleteOne({ _id: user._id }),
        Otp.deleteMany({ userId: user._id }),
      ]);

      return res.status(500).json({
        msg: "Failed to send verification email",
      });
    }

    return res.status(201).json({
      msg: `Account created. Verification code sent to ${email}`,
    });
  } catch (e) {
    await session.abortTransaction();
    session.endSession();

    console.error("Error in register:", e);

    if (e?.code === 11000) {
      return res
        .status(409)
        .json({ msg: "User with this email already exists" });
    }

    return res.status(500).json({ msg: "Internal Server Error" });
  }
});

export default router;
