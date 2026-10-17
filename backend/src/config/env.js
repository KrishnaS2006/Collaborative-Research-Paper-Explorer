import dotenv from "dotenv";

dotenv.config();

const requiredVariables = ["JWT_SECRET", "DATABASE_URL"];

for (const variable of requiredVariables) {
  if (!process.env[variable]) {
    throw new Error(
      `Missing required environment variable: ${variable}`
    );
  }
}

if (process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be at least 32 characters.");
}

export const env = {
  nodeEnv: process.env.NODE_ENV || "development",
  port: Number(process.env.PORT) || 5000,
  databaseUrl: process.env.DATABASE_URL,
  jwtSecret: process.env.JWT_SECRET,
  backendUrl: (process.env.BACKEND_URL || "http://localhost:5000").replace(/\/+$/, ""),
  frontendUrl: (process.env.FRONTEND_URL || "http://localhost:5173").replace(/\/+$/, ""),

  allowedEmailDomains: (
    process.env.ALLOWED_EMAIL_DOMAINS || ""
  )
    .split(",")
    .map((domain) => domain.trim().toLowerCase())
    .filter(Boolean),

  // Institutional OIDC / Google Workspace SSO settings
  sso: {
    enabled: Boolean(
      process.env.OIDC_CLIENT_ID && process.env.OIDC_CLIENT_SECRET
    ),
    issuer: process.env.OIDC_ISSUER || "https://accounts.google.com",
    clientId: process.env.OIDC_CLIENT_ID || "",
    clientSecret: process.env.OIDC_CLIENT_SECRET || "",
    redirectUri:
      process.env.OIDC_REDIRECT_URI ||
      `${(process.env.BACKEND_URL || "http://localhost:5000").replace(/\/+$/, "")}/api/auth/sso/callback`,
    scopes: process.env.OIDC_SCOPES || "openid email profile",
  },
};
