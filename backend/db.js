import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

// Conditionally enable SSL based on connection string or DB_SSL flag
// This allows local PostgreSQL (non-SSL) and Cloud/Neon PostgreSQL (SSL required) to both work smoothly
const isSslRequired = process.env.DATABASE_URL?.includes('sslmode=require') ||
                      process.env.DATABASE_URL?.includes('sslmode=verify') ||
                      process.env.DB_SSL === 'true';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ...(isSslRequired ? { ssl: { rejectUnauthorized: false } } : {})
});

export default pool;