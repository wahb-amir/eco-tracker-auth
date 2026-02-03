import express from "express";
import User from "../../model/User";
import validator from "validator";
import { generateAccessToken, generateRefreshToken } from "../../utils/token";
const router = express.Router();

router.post("/", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ msg: "All fields are required" });
    if (typeof email !== "string" || typeof password !== "string")
      return res.status(400).json({ msg: "Credintials must be a string" });
    if (validator.isEmpty(email))
      return res.status(400).json({ msg: "Credintials cannot be empty" });
    const userDoc = User.findOne(email);
    if (!userDoc) return res.status(404).json({ msg: "User not found" });
    if (userDoc.verified === false)
      return res.status(403).json({ msg: "User not verified" });
    const isMatch = await userDoc.isValidPassword(password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid Credintials" });
    const tokenPayload = {
      email: userDoc.email,
      id: userDoc._id,
      name: userDoc.name,
    };
    const accessToken = generateAccessToken(accessPayload);
    const refreshToken = generateRefreshToken(tokenPayload);
    res.cookie("accessToken", accessToken, {
      httpOnly: true, 
      secure: procces.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 60*60,
    });
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true, 
      secure: procces.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60*7,
    });
    res.status(200).json({message:"Login Successful"});
  } catch (e) {
    console.log("Internal Server Error", e);
    res.status(500).json({ msg: "Internal Server Error" });
  }
});
