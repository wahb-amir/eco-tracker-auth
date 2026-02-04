// routes/register.js
import express from "express";
import User from "../../model/User.js";
import { setUserOtp } from "../../utils/token.js"; 
import { sendOtpEmail } from "../../utils/mailer.js";

const router = express.Router();

router.post("/", async (req, res) => {
  try {
    let { email, password, name } = req.body;

    // basic validation
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

    // normalize
    email = email.trim().toLowerCase();
    name = name.trim();

    // simple email + password checks
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ msg: "Invalid email address" });
    }

    if (password.length < 8) {
      return res
        .status(400)
        .json({ msg: "Password must be at least 8 characters" });
    }

    // check existing user
    const existing = await User.findOne({ email });
    if (existing) {
      return res
        .status(409)
        .json({ msg: "User with this email already exists" });
    }

    // create user document (password hashing handled in model pre-save)
    const userDoc = new User({ name, email, password });

    // Save the user first so we have an _id (the setUserOtp helper may also save, but this is safer)
    await userDoc.save();

    // generate & set OTP on the user. This should save the OTP to the DB and return the plain OTP.
    // setUserOtp(userDoc) must return the plain OTP string (for emailing). Do NOT return this to clients.
    const otp = await setUserOtp(userDoc);

    // send OTP via email (do NOT include OTP in API response)
    try {
      await sendOtpEmail(email, otp, { expiryMinutes: 60 });
    } catch (mailErr) {
      // cleanup created user on email failure (best-effort)
      try {
        await User.deleteOne({ _id: userDoc._id });
      } catch (cleanupErr) {
        console.error("Failed to cleanup user after email error:", cleanupErr);
      }
      console.error("Error sending OTP email:", mailErr);
      return res.status(500).json({ msg: "Failed to send verification email" });
    }

    return res
      .status(201)
      .json({ msg: `Account created. Verification code sent to ${email}` });
  } catch (e) {
    console.error("Error in register:", e);

    // duplicate key error race-case fallback
    if (e && e.code === 11000) {
      return res.status(409).json({ msg: "User with this email already exists" });
    }

    return res.status(500).json({ msg: "Internal Server Error" });
  }
});

export default router;
