import {
  registerUser,
  loginUser,
  getCurrentUserById,
  requestPasswordReset,
  resetUserPassword,
  verifyEmail as verifyEmailService,
  resendVerificationEmail as resendVerificationService,
} from "../services/auth.service.js";

import {
  getSsoConfig as getSsoConfigService,
  generateSsoAuthorizationUrl,
  handleSsoCallback as handleSsoCallbackService,
} from "../services/sso.service.js";

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  maxAge: 8 * 60 * 60 * 1000,
};

const ssoCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  maxAge: 10 * 60 * 1000, // 10 minutes
};

const GENERIC_PASSWORD_RESET_MESSAGE =
  "If an account with that email exists, a password reset link has been sent.";

export const register = async (req, res, next) => {
  try {
    const user = await registerUser(req.body ?? {});

    return res.status(201).json({
      message:
        "User registered successfully. Please check your email to verify your account.",
      user,
    });
  } catch (error) {
    return next(error);
  }
};

export const verifyEmail = async (req, res, next) => {
  try {
    const token = req.body?.token || req.query?.token;
    const result = await verifyEmailService({ token });

    return res.status(200).json(result);
  } catch (error) {
    return next(error);
  }
};

export const resendVerification = async (req, res, next) => {
  try {
    const result = await resendVerificationService(req.body ?? {});

    return res.status(200).json(result);
  } catch (error) {
    return next(error);
  }
};

export const login = async (req, res, next) => {
  try {
    const { token, user } = await loginUser(req.body ?? {});

    res.cookie("token", token, cookieOptions);

    return res.status(200).json({
      message: "Logged in successfully.",
      user,
    });
  } catch (error) {
    return next(error);
  }
};

export const logout = (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  });

  return res.status(200).json({
    message: "Logged out successfully.",
  });
};

export const getCurrentUser = async (req, res, next) => {
  try {
    const user = await getCurrentUserById(req.user._id ?? req.user.id);

    if (!user) {
      return res.status(404).json({
        error: "User not found.",
      });
    }

    return res.status(200).json({ user });
  } catch (error) {
    return next(error);
  }
};

export const forgotPassword = async (req, res, next) => {
  try {
    const result = await requestPasswordReset(req.body ?? {});

    return res.status(200).json({
      message: result?.message || GENERIC_PASSWORD_RESET_MESSAGE,
      ...(result?.devResetToken ? { devResetToken: result.devResetToken } : {}),
    });
  } catch (error) {
    return next(error);
  }
};

export const resetPassword = async (req, res, next) => {
  try {
    const result = await resetUserPassword(req.body ?? {});

    return res.status(200).json({
      message:
        result?.message ??
        "Password has been reset successfully. You can now sign in with your new password.",
    });
  } catch (error) {
    return next(error);
  }
};

/* ==============================================================================
 * SSO CONTROLLER HANDLERS
 * ============================================================================== */

export const getSsoConfig = (req, res) => {
  const config = getSsoConfigService();
  return res.status(200).json(config);
};

export const initiateSso = (req, res, next) => {
  try {
    const { authUrl, state, nonce, codeVerifier } =
      generateSsoAuthorizationUrl();

    // Store state, nonce, and PKCE verifier in secure HTTP-only cookie
    const sessionData = JSON.stringify({ state, nonce, codeVerifier });
    res.cookie("sso_session", sessionData, ssoCookieOptions);

    return res.redirect(authUrl);
  } catch (error) {
    return next(error);
  }
};

export const handleSsoCallback = async (req, res) => {
  const frontendUrl = (
    process.env.FRONTEND_URL || "http://localhost:5173"
  ).replace(/\/+$/, "");

  try {
    const { code, state, error: providerError } = req.query;

    if (providerError) {
      res.clearCookie("sso_session", ssoCookieOptions);
      return res.redirect(
        `${frontendUrl}/login?error=${encodeURIComponent(
          "Single sign-on cancelled or failed: " + providerError
        )}`
      );
    }

    let sessionState = null;
    let sessionNonce = null;
    let sessionCodeVerifier = null;

    if (req.cookies?.sso_session) {
      try {
        const parsed = JSON.parse(req.cookies.sso_session);
        sessionState = parsed.state;
        sessionNonce = parsed.nonce;
        sessionCodeVerifier = parsed.codeVerifier;
      } catch {
        // invalid cookie json
      }
    }

    const { token } = await handleSsoCallbackService({
      code,
      state,
      sessionState,
      sessionNonce,
      sessionCodeVerifier,
    });

    // Clear temporary SSO cookie
    res.clearCookie("sso_session", ssoCookieOptions);

    // Set standard application authentication cookie
    res.cookie("token", token, cookieOptions);

    return res.redirect(`${frontendUrl}/dashboard`);
  } catch (error) {
    res.clearCookie("sso_session", ssoCookieOptions);
    return res.redirect(
      `${frontendUrl}/login?error=${encodeURIComponent(
        error.message || "SSO authentication failed."
      )}`
    );
  }
};

export default {
  register,
  verifyEmail,
  resendVerification,
  login,
  logout,
  getCurrentUser,
  forgotPassword,
  resetPassword,
  getSsoConfig,
  initiateSso,
  handleSsoCallback,
};