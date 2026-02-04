import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const BCRYPT_REGEX = /^\$2[aby]\$(1[0-9]|[2-9][0-9])\$[./A-Za-z0-9]{53}$/;

const userSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    lowercase: true, 
    trim: true 
  },

  password: { 
    type: String, 
    required: true,
    validate: {
      validator(value) {
        return BCRYPT_REGEX.test(value);
      },
      message:
        "Password must be a bcrypt hash. Plaintext passwords are NOT allowed.",
    },
  },

  name: { type: String, required: true },
  verified: { type: Boolean, default: false },

}, {
  timestamps: true
});


userSchema.pre("save", function () {

  if (!this.isModified("password")) return;

  if (!BCRYPT_REGEX.test(this.password)) {
    throw new Error(
      "SECURITY ERROR: Attempted to store a non-bcrypt password."
    );
  }
});



userSchema.pre(["updateOne", "findOneAndUpdate", "updateMany"], function () {

  const update = this.getUpdate();
  if (!update) return;

  const password =
    update.password ||
    update?.$set?.password;

  if (!password) return;

  if (!BCRYPT_REGEX.test(password)) {
    throw new Error(
      "SECURITY ERROR: Attempted to update with a non-bcrypt password."
    );
  }
});


const UserModel =
  mongoose.models.User ||
  mongoose.model("User", userSchema);

export default UserModel;
