import express from "express";
import User from "../../model/User.js";
import { generateVerificationToken } from "../../utils/token.js";
import { sendVerificationEmail } from "../../utils/mailer.js";

const router = express.Router();

router.post("/", async (req, res) => {
  try {
    let { email, password, name } = req.body;

    // basic validation
    if (!email || !password || !name)
      return res.status(400).json({ msg: "All fields are required" });

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      typeof name !== "string"
    ) {
      return res.status(400).json({ msg: "Credentials must be strings" });
    }

    // normalize email
    email = email.trim().toLowerCase();
    name = name.trim();

    // Optional: simple email format check
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email))
      return res.status(400).json({ msg: "Invalid email address" });

    // Check for existing user (race condition still possible — see note below)
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ msg: "User with this email already exists" });
    }

    // Create user doc (password hashing handled by pre-save hook)
    const userDoc = new User({ name, email, password });

    // You can generate token now — _id is available even before save
    const token = generateVerificationToken({ email, id: userDoc._id }, "1h");
    userDoc.setVerificationToken(token);

    // Save user
    await userDoc.save();

    // Send verification email. If sending fails, remove the created user to avoid orphaned records.
    try {
      await sendVerificationEmail(email, token);
    } catch (mailErr) {
      // attempt to cleanup the created user
      try {
        await User.deleteOne({ _id: userDoc._id });
      } catch (cleanupErr) {
        console.error("Failed to cleanup user after email error:", cleanupErr);
      }
      console.error("Error sending verification email:", mailErr);
      return res.status(500).json({ msg: "Failed to send verification email" });
    }

    return res
      .status(201)
      .json({ message: `Please verify your account at ${email}` });
  } catch (e) {
    console.error("Error in register:", e);

    if (e && e.code === 11000) {
      return res.status(409).json({ msg: "User with this email already exists" });
    }

    return res.status(500).json({ msg: "Internal Server Error" });
  }
});

export default router;
