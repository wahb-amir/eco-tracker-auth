// src/api/auth/verify.js
import express from "express";
import jwt from "jsonwebtoken";
import User from "../../../model/User.js";
import { verifyVerificationToken } from "../../../utils/token.js";
const router = express.Router();

router.get("/info", async (req, res) => {
  try{
     const token = req.cookies.verificationToken;
     if(!token)
      res.status(400).json({ error: "Unauthorized" })
     const decoded = verifyVerificationToken(token);
     console.log(decoded)
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


    if (!otp || typeof otp !== "string" || !/^\d{6}$/.test(otp.trim())) {
      return res.status(400).json({ error: "OTP is required and must be a 6-digit string" });
    }
    const otpValue = otp.trim();

   
    let user = null;
    const token = req.cookies?.verificationToken;

    if (token) {
      try {
        const decoded = verifyVerificationToken(token);
        if (!decoded || !decoded.uid) {
          return res.status(401).json({ error: "Invalid verification token" });
        }
        user = await User.findById(decoded.uid);
      } catch (err) {
        console.log(err)
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
      console.log(result)
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
