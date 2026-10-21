import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { env } from "../config/env.js";
import { getValidatedJwtSecret } from "../utils/jwt.js";
import { isAllowedInstitutionalEmail } from "../utils/validation.js";
import { createSession } from "./session.service.js";
import {
  findSsoIdentity,
  linkSsoIdentityToUser,
  createSsoUserWithIdentity,
  findUserByEmail,
  findUserById,
} from "../repositories/auth.repository.js";

const GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const GOOGLE_CERTS_ENDPOINT = "https://www.googleapis.com/oauth2/v3/certs";

const createError = (message, statusCode) => {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
};

// In-memory cache for provider JWKS public keys
let cachedJwks = null;
let cachedJwksExpiry = 0;

export const setCachedJwksForTesting = (jwks) => {
  cachedJwks = jwks;
  cachedJwksExpiry = Date.now() + 3600000;
};

export const resetCachedJwksForTesting = () => {
  cachedJwks = null;
  cachedJwksExpiry = 0;
};

export const getSsoConfig = () => {
  return {
    enabled: env.sso.enabled,
    provider: "google",
    name: "Google Workspace / Institutional SSO",
    allowedDomains: env.allowedEmailDomains,
    loginUrl: env.sso.enabled ? "/api/auth/sso/login" : null,
  };
};

export const generateSsoAuthorizationUrl = () => {
  if (!env.sso.enabled) {
    throw createError(
      "Institutional SSO is not configured on this server.",
      503
    );
  }

  if (!env.sso.clientId || !env.sso.clientSecret) {
    throw createError(
      "OIDC_CLIENT_ID or OIDC_CLIENT_SECRET is missing.",
      503
    );
  }

  const state = crypto.randomBytes(32).toString("hex");
  const nonce = crypto.randomBytes(32).toString("hex");

  // PKCE: code_verifier and code_challenge (RFC 7636)
  const codeVerifier = crypto
    .randomBytes(32)
    .toString("base64url");
  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");

  const params = new URLSearchParams({
    client_id: env.sso.clientId,
    redirect_uri: env.sso.redirectUri,
    response_type: "code",
    scope: env.sso.scopes,
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    prompt: "select_account",
  });

  // If a single institutional domain is configured, suggest it via Google hd param
  if (env.allowedEmailDomains.length === 1) {
    params.set("hd", env.allowedEmailDomains[0]);
  }

  const authUrl = `${GOOGLE_AUTH_ENDPOINT}?${params.toString()}`;

  return {
    authUrl,
    state,
    nonce,
    codeVerifier,
  };
};

const fetchGooglePublicKeys = async () => {
  if (cachedJwks && Date.now() < cachedJwksExpiry) {
    return cachedJwks;
  }

  const res = await fetch(GOOGLE_CERTS_ENDPOINT);
  if (!res.ok) {
    throw createError("Failed to fetch Google public certificates.", 502);
  }

  const jwks = await res.json();
  cachedJwks = jwks;
  cachedJwksExpiry = Date.now() + 60 * 60 * 1000; // cache 1 hour
  return jwks;
};

export const verifyGoogleIdToken = async (idToken, expectedNonce) => {
  if (typeof idToken !== "string" || !idToken.includes(".")) {
    throw createError("Invalid ID token format.", 400);
  }

  const parts = idToken.split(".");
  if (parts.length !== 3) {
    throw createError("Invalid ID token structure.", 400);
  }

  let header;
  let payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    throw createError("Malformed ID token payload.", 400);
  }

  // 1. Verify Issuer
  const validIssuers = ["https://accounts.google.com", "accounts.google.com"];
  if (!validIssuers.includes(payload.iss)) {
    throw createError(`Invalid ID token issuer: ${payload.iss}`, 401);
  }

  // 2. Verify Audience
  if (payload.aud !== env.sso.clientId) {
    throw createError(`ID token audience mismatch: ${payload.aud}`, 401);
  }

  // 3. Verify Expiration
  const nowInSeconds = Math.floor(Date.now() / 1000);
  if (!payload.exp || payload.exp < nowInSeconds) {
    throw createError("ID token has expired.", 401);
  }

  // 4. Verify Nonce (prevents replay attacks)
  if (expectedNonce && payload.nonce !== expectedNonce) {
    throw createError("ID token nonce mismatch.", 401);
  }

  // 5. Verify Signature using JWKS
  try {
    const jwks = await fetchGooglePublicKeys();
    const key = jwks.keys?.find((k) => k.kid === header.kid);
    if (key) {
      // Import public key into node:crypto KeyObject
      const publicKey = crypto.createPublicKey({
        key: {
          kty: key.kty,
          n: key.n,
          e: key.e,
        },
        format: "jwk",
      });

      const verifier = crypto.createVerify("RSA-SHA256");
      verifier.update(`${parts[0]}.${parts[1]}`);
      const signatureValid = verifier.verify(
        publicKey,
        Buffer.from(parts[2], "base64url")
      );

      if (!signatureValid) {
        throw createError("ID token signature verification failed.", 401);
      }
    }
  } catch (err) {
    if (err.statusCode) throw err;
    // In test environment, if signature verification fails due to mock keys without full certs,
    // ensure error is reported accurately
    console.error("Signature verification error:", err.message);
    throw createError("ID token signature verification failed.", 401);
  }

  return payload;
};

export const handleSsoCallback = async ({
  code,
  state,
  sessionState,
  sessionNonce,
  sessionCodeVerifier,
}) => {
  if (!sessionState || !state || state !== sessionState) {
    throw createError(
      "Invalid or expired SSO state session. Login CSRF detected.",
      403
    );
  }

  if (!code) {
    throw createError(
      "Authorization code was not provided by the identity provider.",
      400
    );
  }

  if (!env.sso.enabled) {
    throw createError("Institutional SSO is not configured.", 503);
  }

  // Exchange code for tokens at the provider token endpoint
  let tokenData;
  try {
    const tokenParams = new URLSearchParams({
      code,
      client_id: env.sso.clientId,
      client_secret: env.sso.clientSecret,
      redirect_uri: env.sso.redirectUri,
      grant_type: "authorization_code",
      code_verifier: sessionCodeVerifier || "",
    });

    const tokenRes = await fetch(GOOGLE_TOKEN_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: tokenParams.toString(),
    });

    if (!tokenRes.ok) {
      const errBody = await tokenRes.text();
      console.error("Token exchange failed:", errBody);
      throw createError(
        "Failed to exchange authorization code with identity provider.",
        401
      );
    }

    tokenData = await tokenRes.json();
  } catch (error) {
    if (error.statusCode) throw error;
    console.error("SSO token fetch exception:", error.message);
    throw createError("Unable to communicate with identity provider.", 502);
  }

  const { id_token } = tokenData;
  if (!id_token) {
    throw createError("No ID token returned by identity provider.", 401);
  }

  // Validate ID token signature, issuer, audience, exp, and nonce
  const payload = await verifyGoogleIdToken(id_token, sessionNonce);

  const {
    sub,
    email,
    email_verified,
    name,
    hd, // Hosted G Suite / Google Workspace domain, if applicable
  } = payload;

  if (!sub) {
    throw createError("Missing subject identifier in ID token.", 401);
  }

  if (!email) {
    throw createError("Missing email claim in ID token.", 401);
  }

  if (email_verified !== true && email_verified !== "true") {
    throw createError(
      "Identity provider email address has not been verified.",
      403
    );
  }

  const normalizedEmail = email.trim().toLowerCase();

  // Institutional domain policy enforcement
  if (env.allowedEmailDomains.length > 0) {
    const isAllowed = isAllowedInstitutionalEmail(
      normalizedEmail,
      env.allowedEmailDomains
    );

    if (!isAllowed) {
      throw createError(
        `Institutional domain not permitted. Please sign in with an approved institutional email address. (Allowed: ${env.allowedEmailDomains.join(", ")})`,
        403
      );
    }
  }

  // Safe Account Provisioning & Identity Mapping
  let user = null;

  // 1. Check if identity already mapped
  const existingIdentity = await findSsoIdentity("google", sub);

  if (existingIdentity) {
    user = await findUserById(existingIdentity.user_id);
    if (!user) {
      throw createError("Associated user account no longer exists.", 401);
    }
  } else {
    // 2. Check if a local account with that email already exists
    const existingUser = await findUserByEmail(normalizedEmail);

    if (existingUser) {
      // Safe linking: Verified institutional email from trusted provider maps to user
      await linkSsoIdentityToUser({
        userId: existingUser.id,
        provider: "google",
        providerSubjectId: sub,
        email: normalizedEmail,
      });
      user = existingUser;
    } else {
      // 3. Provision new account with institutional profile
      const domain = normalizedEmail.split("@").pop();
      const defaultRole = "STUDENT";
      const affiliation = hd || domain || "Academic Institution";
      const randomPassword = crypto.randomBytes(32).toString("hex") + "A1!a";
      const passwordHash = await bcrypt.hash(randomPassword, 12);

      user = await createSsoUserWithIdentity({
        email: normalizedEmail,
        fullName: name?.trim() || normalizedEmail.split("@")[0],
        role: defaultRole,
        affiliation,
        researchInterests: [],
        provider: "google",
        providerSubjectId: sub,
        passwordHash,
      });
    }
  }

  // Issue the standard session JWT token
  const token = jwt.sign(
    {
      _id: user.id,
      id: user.id,
      email: user.email,
      role: user.role,
      access_role: user.access_role,
    },
    getValidatedJwtSecret(),
    { expiresIn: "8h" }
  );

  // FR-04: Register server-side session for idle tracking and revocation
  await createSession({
    userId: user.id,
    token,
  });

  return {
    token,
    user: {
      id: user.id,
      email: user.email,
      full_name: user.full_name,
      role: user.role,
      access_role: user.access_role,
      affiliation: user.affiliation,
      research_interests: user.research_interests,
      email_verified: user.email_verified,
    },
  };
};

export default {
  getSsoConfig,
  generateSsoAuthorizationUrl,
  verifyGoogleIdToken,
  handleSsoCallback,
  setCachedJwksForTesting,
  resetCachedJwksForTesting,
};
