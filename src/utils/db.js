// middleware/dbConnect.js
import mongoose from "mongoose";

const MONGO_URI = process.env.MONGO_URI;

const connectWithRetry = (retries = 5, delay = 2000) => {
  let isConnected = false;

  // Return middleware function
  return async (req, res, next) => {
    if (isConnected) return next(); // Already connected

    const connect = async (remainingRetries) => {
      try {
        await mongoose.connect(MONGO_URI, {
          useNewUrlParser: true,
          useUnifiedTopology: true,
        });
        console.log("✅ MongoDB connected successfully!");
        isConnected = true;
        next();
      } catch (err) {
        console.error(
          `❌ MongoDB connection failed. Retries left: ${remainingRetries}`,
          err.message
        );
        if (remainingRetries > 0) {
          console.log(`⏳ Retrying in ${delay / 1000} seconds...`);
          setTimeout(() => connect(remainingRetries - 1), delay);
        } else {
          console.error("🚨 Could not connect to MongoDB. Exiting...");
          res.status(500).json({ error: "Database connection failed" });
        }
      }
    };

    connect(retries);
  };
};

export default connectWithRetry;
