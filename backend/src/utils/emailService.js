
// backend/src/services/email.service.js

import nodemailer from "nodemailer";

let testTransporter = null;

/**
 * Inject a mock transporter for automated tests.
 * Pass null to restore the default transporter.
 */
export const setTransporterForTesting = (transporter) => {
  testTransporter = transporter;
};

/**
 * Backward-compatible alias for existing tests.
 */
export const _setTransporterForTesting = setTransporterForTesting;

export const resetTransporterForTesting = () => {
  testTransporter = null;
};

export const _resetTransporterForTesting =
  resetTransporterForTesting;

/**
 * Creates an SMTP transporter.
 *
 * SMTP_PORT=465 -> SSL
 * SMTP_PORT=587 -> STARTTLS
 */
export const createSmtpTransporter = () => {
  if (testTransporter) {
    return testTransporter;
  }

  const host = process.env.SMTP_HOST || "smtp.gmail.com";
  const port = Number(process.env.SMTP_PORT) || 587;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!user || !pass) {
    throw new Error(
      "SMTP_USER or SMTP_PASS environment variable is missing."
    );
  }

  return nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: {
      user,
      pass,
    },
    tls: {
      // Always verify TLS certificates.
      rejectUnauthorized: true,
    },
  });
};

/**
 * Sends a password-reset email.
 *
 * @param {object} params
 * @param {string} params.to Recipient email
 * @param {string} [params.name] Recipient name
 * @param {string} params.resetToken Raw reset token
 * @param {string} [params.resetUrl] Optional reset URL override
 */
export const sendPasswordResetEmail = async ({
  to,
  name,
  resetToken,
  resetUrl,
}) => {
  if (
    typeof to !== "string" ||
    !to.trim() ||
    typeof resetToken !== "string" ||
    !resetToken
  ) {
    throw new Error("Recipient email and reset token are required.");
  }

  const isProduction = process.env.NODE_ENV === "production";
  const frontendUrl = (
    process.env.FRONTEND_URL || "http://localhost:5173"
  ).replace(/\/+$/, "");

  const targetUrl =
    resetUrl ||
    `${frontendUrl}/reset-password?token=${encodeURIComponent(
      resetToken
    )}`;

  let mode = (
    process.env.EMAIL_SERVICE_MODE || ""
  ).trim().toLowerCase();

  if (!mode) {
    if (process.env.SMTP_USER && process.env.SMTP_PASS) {
      mode = "smtp";
    } else {
      mode = isProduction ? "disabled" : "console";
    }
  }

  if (!["smtp", "console", "disabled"].includes(mode)) {
    throw new Error(
      "EMAIL_SERVICE_MODE must be smtp, console, or disabled."
    );
  }

  // Development-only mode. Never print reset links in production.
  if (mode === "console") {
    if (isProduction) {
      console.error(
        "Console email mode is not permitted in production."
      );

      return {
        success: false,
        mode: "console",
        error: "Console email mode is not permitted in production.",
      };
    }

    console.log(
      "\n========== [DEVELOPMENT EMAIL] =========="
    );
    console.log(`To: ${to}`);
    console.log(
      `Name: ${name || "Researcher"}`
    );
    console.log(
      "Subject: Password Reset Request - Collaborative Research Paper Explorer"
    );
    console.log(`Reset link: ${targetUrl}`);
    console.log("Validity: 15 minutes; single use");
    console.log("=========================================\n");

    return {
      success: true,
      mode: "console",
      targetUrl,
    };
  }

  if (mode === "disabled") {
    if (isProduction) {
      console.warn(
        "Password-reset email delivery is disabled."
      );
    }

    return {
      success: false,
      mode: "disabled",
    };
  }

  // SMTP mode
  let transporter;

  try {
    transporter = createSmtpTransporter();
  } catch (error) {
    console.error(
      "SMTP configuration failed:",
      error.message
    );

    return {
      success: false,
      mode: "smtp",
      error: "Email service is not configured correctly.",
    };
  }

  const sender =
    process.env.SMTP_FROM ||
    `"Collaborative Research Paper Explorer" <${process.env.SMTP_USER}>`;

  const recipientName = name?.trim() || "Researcher";

  const subject =
    "Password Reset Request - Collaborative Research Paper Explorer";

  const text = `Hello ${recipientName},

We received a request to reset your password for the Collaborative Research Paper Explorer.

Use the following link to choose a new password:
${targetUrl}

This link is valid for 15 minutes and can only be used once.

If you did not request this password reset, you can ignore this email.

Best regards,
The Collaborative Research Paper Explorer Team`;

  // Escape interpolated values before inserting them into HTML.
  const escapeHtml = (value) =>
    String(value).replace(/[&<>"']/g, (character) => {
      const entities = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      };

      return entities[character];
    });

  const safeName = escapeHtml(recipientName);
  const safeEmail = escapeHtml(to);
  const safeUrl = escapeHtml(targetUrl);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Password Reset Request</title>
</head>
<body style="font-family:Arial,sans-serif;background:#f8fafc;color:#334155;padding:24px">
  <div style="max-width:560px;margin:auto;background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:32px">
    <h1 style="color:#0f172a;text-align:center">Research Paper Explorer</h1>
    <p style="text-align:center;color:#64748b">Password Reset Request</p>

    <p>Hello <strong>${safeName}</strong>,</p>
    <p>We received a request to reset the password for the account associated with <strong>${safeEmail}</strong>.</p>

    <p style="text-align:center;margin:28px 0">
      <a href="${safeUrl}" style="background:#4f46e5;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;display:inline-block">
        Reset My Password
      </a>
    </p>

    <p>This link is valid for 15 minutes and can only be used once. If you did not request this, you can ignore this email.</p>

    <p>If the button does not work, copy this link into your browser:</p>
    <p style="word-break:break-all"><a href="${safeUrl}">${safeUrl}</a></p>

    <hr style="border:0;border-top:1px solid #e2e8f0;margin-top:28px">
    <p style="text-align:center;color:#94a3b8;font-size:12px">
      Collaborative Research Paper Explorer
    </p>
  </div>
</body>
</html>`;

  try {
    const info = await transporter.sendMail({
      from: sender,
      to: to.trim(),
      subject,
      text,
      html,
    });

    // Do not log recipient addresses or reset URLs in production.
    if (!isProduction) {
      console.log(
        `[EMAIL SUCCESS] Password-reset email sent. Message ID: ${info.messageId}`
      );
    }

    return {
      success: true,
      mode: "smtp",
      messageId: info.messageId,
    };
  } catch (error) {
    // Avoid returning SMTP details to public API responses.
    console.error(
      "Password-reset email delivery failed:",
      error.message
    );

    return {
      success: false,
      mode: "smtp",
      error: "Password-reset email could not be delivered.",
    };
  }
};

export default sendPasswordResetEmail;
