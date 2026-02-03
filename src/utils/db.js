// dbConnect.js
import mongoose from "mongoose";

const connectWithRetry = async (mongoUri, retries = 5, delay = 2000) => {
  let isConnected = false;

  const connect = async (remainingRetries) => {
    try {
      await mongoose.connect(mongoUri);
      console.log("✅ MongoDB connected successfully!");
      isConnected = true;
    } catch (err) {
      console.error(
        `❌ MongoDB connection failed. Retries left: ${remainingRetries}`,
        err.message
      );

      if (remainingRetries > 0) {
        console.log(`⏳ Retrying in ${delay / 1000} seconds...`);
        await new Promise((res) => setTimeout(res, delay));
        return connect(remainingRetries - 1);
      } else {
        console.error("🚨 Could not connect to MongoDB. Exiting...");
        process.exit(1);
      }
    }
  };

  if (!isConnected) {
    await connect(retries);
  }
};

export default connectWithRetry;
