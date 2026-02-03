import jwt from "jsonwebtoken";

const ACCESS_TOKEN=process.env.ACCESS_TOKEN;
const REFRESH_TOKEN=process.env.REFRESH_TOKEN;

export const generateAccessToken = (user) => {
  return jwt.sign(user, ACCESS_TOKEN, { expiresIn: "15m" });
};

export const generateRefreshToken = (user) => {
  return jwt.sign(user, REFRESH_TOKEN),{expiresIn:"7d"};
};

export const verifyAccessToken = (token) => {
  return jwt.verify(token, ACCESS_TOKEN);
};

export const verifyRefreshToken = (token) => {
  return jwt.verify(token, REFRESH_TOKEN);
};