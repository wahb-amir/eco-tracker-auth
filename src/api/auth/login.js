import express from "express";
import User from "../../model/User.js";
import validator from "validator";
import { generateAccessToken, generateRefreshToken } from "../../utils/token.js";
import bcrypt from "bcryptjs";

const router = express.Router();

router.post("/", async (req, res) => {
  try {
    let { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ msg: "All fields are required" });
    if (typeof email !== "string" || typeof password !== "string")
      return res.status(400).json({ msg: "Credentials must be strings" });

    email = email.trim().toLowerCase();
    password = password.trim();
    if (!validator.isEmail(email)) return res.status(400).json({ msg: "Invalid email" });
    if (validator.isEmpty(password)) return res.status(400).json({ msg: "Password cannot be empty" });

    const userDoc = await User.findOne({ email });
    if (!userDoc) return res.status(404).json({ msg: "User not found" });


    if (!userDoc.verified) return res.status(403).json({ msg: "User not verified" });

    if (!userDoc.password) return res.status(500).json({ msg: "User has no password set" });

    const isMatch = await bcrypt.compare(password, userDoc.password);
    if (!isMatch) return res.status(401).json({ msg: "Invalid credentials" });

    // Prepare token payload and generate tokens
    const tokenPayload = {
      email: userDoc.email,
      id: userDoc._id,
      name: userDoc.name,
    };

    const accessToken = generateAccessToken(tokenPayload);
    const refreshToken = generateRefreshToken(tokenPayload);
    console.log(refreshToken)
    
    const isProd = process.env.NODE_ENV === "production";
    const accessMaxAge = 60 * 60 * 1000; // 1 hour in ms
    const refreshMaxAge = 7 * 24 * 60 * 60 * 1000; // 7 days in ms

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: accessMaxAge,
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: refreshMaxAge,
    });

    return res.status(200).json({ message: "Login successful" });
  } catch (e) {
    console.error("Internal Server Error", e);

    return res.status(500).json({ msg: "Internal Server Error" });
  }
});

export default router;
