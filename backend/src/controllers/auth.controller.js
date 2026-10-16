
import {
  registerUser,
  loginUser,
  getCurrentUserById,
  requestPasswordReset,
  resetUserPassword,
} from "../services/auth.service.js";

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  maxAge: 8 * 60 * 60 * 1000,
};

const GENERIC_PASSWORD_RESET_MESSAGE =
  "If an account with that email exists, a password reset link has been sent.";

export const register = async (req, res, next) => {
  try {
    const user = await registerUser(req.body ?? {});

    return res.status(201).json({
      message: "User registered successfully.",
      user,
    });
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
    await requestPasswordReset(req.body ?? {});

    // Same response for existing and non-existing email addresses.
    return res.status(200).json({
      message: GENERIC_PASSWORD_RESET_MESSAGE,
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

export default {
  register,
  login,
  logout,
  getCurrentUser,
  forgotPassword,
  resetPassword,
};