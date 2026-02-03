import express from "express";
import User from "../../model/User";
import validator from "validator";
import { generateVerificationToken } from "../../utils/token";

const router = express.Router();

router.post("/", async(req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name)
      return res.status(400).json({ msg: "All fields are required" });
    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      typeof name !== "string"
    ) {
      return res.status(400).json({ msg: "Credintials must be a string" });
    }
    if (validator.isEmail(email))
      return res.status(400).json({ msg: "Invalid Email" });

    /** @type {any} */
    const userDoc = new User({
        name,
        email,
        password
    })
    const token = generateVerificationToken({email,id:userDoc._id},"1h")

    userDoc.setVerificationToken(token);
    await userDoc.save()
    return res.status(200).json({message:`Please verify your account at ${email}`})
  } catch (e) {
    console.log("Error in register:", e);
    res.status(500).json({ msg: "Internal Server Error" });
  }
});

export default router
