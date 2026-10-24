// backend/src/test/setup.js
// Standard test environment initialization.
// Ensures mandatory environment variables are populated before configuration modules load.

import dotenv from "dotenv";
dotenv.config();

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  process.env.JWT_SECRET = "super_secure_test_jwt_secret_with_32_characters_12345";
}

if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/collaborative_research_test";
}

if (!process.env.NODE_ENV) {
  process.env.NODE_ENV = "test";
}

process.env.EXPOSE_DEV_RESET_TOKEN = "true";
