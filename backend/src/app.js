
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

import authRoutes from "./routes/auth.routes.js";
import errorHandler from "./middleware/errorHandler.js";

const app = express();

app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:5173",
    credentials: true,
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

// Health-check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    message: "Research Paper Explorer API is running!",
  });
});

// API routes
app.use("/api/auth", authRoutes);

// Handle unknown routes
app.use((req, res) => {
  res.status(404).json({
    error: "Route not found.",
  });
});

// Error handler must be registered last
app.use(errorHandler);

export default app;
