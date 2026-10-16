
import pg from "pg";
import { env } from "./env.js";

const { Pool } = pg;

const pool = new Pool({
  connectionString: env.databaseUrl,

  ...(env.nodeEnv === "production"
    ? { ssl: { rejectUnauthorized: true } }
    : {}),
});

pool.on("error", (error) => {
  console.error("Unexpected PostgreSQL pool error:", error.message);
});

export const connectDatabase = async () => {
  const client = await pool.connect();

  try {
    await client.query("SELECT 1");
    console.log("PostgreSQL connected successfully.");
  } finally {
    client.release();
  }
};

export default pool;
