import dotenv from "dotenv";

dotenv.config({
  path: "./.env",
});

import app from "./app.js";
import connectDB from "./db/db-connection.js";

const port = process.env.PORT || 3002;

connectDB()
  .then(() => {
    app.listen(port, () => {
      console.log(`🚀 Server running at http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
  });



