// src/api/auth/verify.js
import express from "express";
import jwt from "jsonwebtoken";
import User from "../../../model/User.js";

const router = express.Router();

router.get("/", async (req, res) => {
  try{
     const token = req.cookies.verificationToken;
     if(!token)
      res.status(400).json({ error: "Unauthorized" })
     const decoded = jwt.verify(token, process.env.VERIFICATION_TOKEN);
     if(!decoded || !decoded.uid || !decoded.email)
      return res.status(401).json({ error: "Invalid token" })
    return res.status(200).json({email: decoded.email })
  }
  catch(e){
    console.log("error in verify get:",e)
    return res.status(500).json({ error: "Internal Server Error" });
  }
})
router.post("/", async (req, res) => {
  try {
    const { otp, email: emailFromBody } = req.body;

    // validate OTP presence & shape
    if (!otp || typeof otp !== "string" || !/^\d{6}$/.test(otp.trim())) {
      return res.status(400).json({ error: "OTP is required and must be a 6-digit string" });
    }
    const otpValue = otp.trim();

    // Try to identify the user: first from cookie (JWT), fallback to email in body
    let user = null;
    const token = req.cookies?.verificationToken;

    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.VERIFICATION_TOKEN_SECRET);
        if (!decoded || !decoded.uid) {
          return res.status(401).json({ error: "Invalid verification token" });
        }
        user = await User.findById(decoded.uid);
      } catch (err) {
        // token invalid or expired
        return res.status(401).json({ error: "Invalid or expired verification token" });
      }
    } else if (emailFromBody && typeof emailFromBody === "string") {
      user = await User.findOne({ email: emailFromBody.toLowerCase().trim() });
    } else {
      return res.status(401).json({ error: "No verification token or email provided" });
    }

    if (!user) return res.status(404).json({ error: "User not found" });

    const result = await user.verifyOtp(otpValue);

    if (!result.ok) {
      if (result.reason === "expired") {
        return res.status(410).json({ error: "OTP expired" });
      }
      if (result.reason === "invalid") {
        return res.status(401).json({ error: "Incorrect OTP" });
      }
      return res.status(400).json({ error: "OTP not set" });
    }

    res.clearCookie("verificationToken", { httpOnly: true, path: "/" });
    return res.json({ message: "Verified" });
  } catch (e) {
    console.error("error in verify post", e);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});
export default router;
