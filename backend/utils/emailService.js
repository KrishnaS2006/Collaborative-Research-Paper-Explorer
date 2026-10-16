import nodemailer from 'nodemailer';

/**
 * ARCHITECTURAL & SECURITY NOTES:
 * ------------------------------
 * 1. Modes:
 *    - 'smtp': Transports real emails via SMTP (e.g. Gmail SMTP: smtp.gmail.com:587 with STARTTLS).
 *    - 'console': Logs formatted reset link to stdout (ideal for offline development).
 *    - 'disabled': Skips email sending.
 * 2. Gmail SMTP Requirements:
 *    - Host: smtp.gmail.com
 *    - Port: 587 (STARTTLS) or 465 (SSL)
 *    - Requires Google Account with 2-Step Verification and a 16-character App Password.
 *    - Passwords must be placed strictly in local backend/.env and never committed.
 * 3. Token Security:
 *    - Plaintext reset tokens are only transmitted to the recipient's verified email address.
 *    - Plaintext tokens are never logged or exposed in production environments.
 */

// Injected transporter for unit testing (avoids sending real emails during test runs)
let testTransporter = null;

/**
 * Sets a custom or mocked transporter for automated testing.
 * @param {object|null} transporter
 */
export const _setTransporterForTesting = (transporter) => {
  testTransporter = transporter;
};

/**
 * Resets the testing transporter back to default.
 */
export const _resetTransporterForTesting = () => {
  testTransporter = null;
};

/**
 * Creates and returns a Nodemailer transporter configured with environment variables.
 * @returns {nodemailer.Transporter}
 */
export const createSmtpTransporter = () => {
  if (testTransporter) {
    return testTransporter;
  }

  const host = process.env.SMTP_HOST || 'smtp.gmail.com';
  const port = Number(process.env.SMTP_PORT) || 587;
  const isSecure = port === 465; // Port 465 uses SSL; 587 uses STARTTLS (secure: false)

  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!user || !pass) {
    throw new Error('SMTP_USER or SMTP_PASS environment variable is missing.');
  }

  return nodemailer.createTransport({
    host,
    port,
    secure: isSecure,
    auth: {
      user,
      pass,
    },
    // Strict TLS verification
    tls: {
      rejectUnauthorized: process.env.NODE_ENV === 'production', // Only reject unauthorized certs in production
    },
  });
};

/**
 * Sends a password reset email using the configured delivery mode (SMTP or Console).
 * @param {object} params
 * @param {string} params.to - Recipient email address
 * @param {string} [params.name] - Recipient full name
 * @param {string} params.resetToken - Raw unhashed reset token
 * @param {string} [params.resetUrl] - Optional direct reset URL override
 * @returns {Promise<{ success: boolean, mode: string, messageId?: string, error?: string, targetUrl?: string }>}
 */
export const sendPasswordResetEmail = async ({ to, name, resetToken, resetUrl }) => {
  const isProduction = process.env.NODE_ENV === 'production';
  const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
  const targetUrl = resetUrl || `${frontendUrl}/reset-password?token=${encodeURIComponent(resetToken)}`;

  // Determine active mode:
  // If explicitly configured, respect EMAIL_SERVICE_MODE.
  // Otherwise, default to 'smtp' if credentials exist, or 'console' in dev.
  let mode = process.env.EMAIL_SERVICE_MODE;
  if (!mode) {
    if (process.env.SMTP_USER && process.env.SMTP_PASS) {
      mode = 'smtp';
    } else {
      mode = isProduction ? 'disabled' : 'console';
    }
  }

  // --- 1. Console Development Mode ---
  if (mode === 'console') {
    if (!isProduction) {
      console.log('\n================== [DEV EMAIL SERVICE] ==================');
      console.log(`To:      ${to} ${name ? `(${name})` : ''}`);
      console.log('Subject: Password Reset Request - Collaborative Research Paper Explorer');
      console.log(`Link:    ${targetUrl}`);
      console.log('TTL:     15 minutes (Single-use token)');
      console.log('=========================================================\n');
    }
    return {
      success: true,
      mode: 'console',
      targetUrl,
    };
  }

  // --- 2. Real SMTP Delivery Mode ---
  if (mode === 'smtp') {
    let transporter;
    try {
      transporter = createSmtpTransporter();
    } catch (configErr) {
      console.error('[EMAIL ERROR] SMTP configuration failed:', configErr.message);
      return {
        success: false,
        mode: 'smtp',
        error: configErr.message,
      };
    }

    const sender =
      process.env.SMTP_FROM ||
      (process.env.SMTP_USER
        ? `"Collaborative Research Paper Explorer" <${process.env.SMTP_USER}>`
        : '"Collaborative Research Paper Explorer" <noreply@example.com>');

    const recipientName = name ? name : 'Researcher';

    const textContent = `Hello ${recipientName},

We received a request to reset your password for the Collaborative Research Paper Explorer.

Please use the following link to choose a new password:
${targetUrl}

This link is valid for 15 minutes and can only be used once.

If you did not request this password reset, please ignore this email. Your account remains secure.

Best regards,
The Collaborative Research Paper Explorer Team`;

    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; color: #1e293b; margin: 0; padding: 24px; }
    .container { max-width: 560px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; padding: 32px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }
    .header { text-align: center; margin-bottom: 24px; }
    .title { font-size: 20px; font-weight: bold; color: #0f172a; margin: 0 0 8px; }
    .subtitle { font-size: 14px; color: #64748b; margin: 0; }
    .content { font-size: 14px; line-height: 1.6; color: #334155; margin-bottom: 24px; }
    .btn-container { text-align: center; margin: 28px 0; }
    .btn { background-color: #4f46e5; color: #ffffff !important; padding: 12px 28px; border-radius: 8px; font-weight: 600; text-decoration: none; display: inline-block; font-size: 14px; }
    .btn:hover { background-color: #4338ca; }
    .note { background-color: #f1f5f9; border-left: 4px solid #6366f1; padding: 12px 16px; border-radius: 4px; font-size: 13px; color: #475569; margin: 20px 0; }
    .footer { font-size: 12px; color: #94a3b8; text-align: center; border-top: 1px solid #f1f5f9; padding-top: 20px; margin-top: 28px; }
    .url-fallback { word-break: break-all; font-size: 12px; color: #6366f1; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1 class="title">Research Paper Explorer</h1>
      <p class="subtitle">Password Reset Request</p>
    </div>
    <div class="content">
      <p>Hello <strong>${recipientName}</strong>,</p>
      <p>We received a request to reset the password for your account associated with <strong>${to}</strong>.</p>
      <div class="btn-container">
        <a href="${targetUrl}" class="btn" target="_blank" rel="noopener noreferrer">Reset My Password</a>
      </div>
      <div class="note">
        <strong>Security Notice:</strong> This link is valid for <strong>15 minutes</strong> and can only be used once. If you did not request this password reset, you can safely ignore this email.
      </div>
      <p>If the button above does not work, copy and paste this link into your web browser:</p>
      <p><a href="${targetUrl}" class="url-fallback">${targetUrl}</a></p>
    </div>
    <div class="footer">
      Collaborative Research Paper Explorer &bull; Secure Authentication System
    </div>
  </div>
</body>
</html>`;

    try {
      const info = await transporter.sendMail({
        from: sender,
        to,
        subject: 'Password Reset Request - Collaborative Research Paper Explorer',
        text: textContent,
        html: htmlContent,
      });

      console.log(`[EMAIL SUCCESS] Password reset email sent to ${to} (Message ID: ${info.messageId})`);
      return {
        success: true,
        mode: 'smtp',
        messageId: info.messageId,
      };
    } catch (sendErr) {
      console.error('[EMAIL ERROR] Failed to send password reset email via SMTP:', sendErr.message);
      return {
        success: false,
        mode: 'smtp',
        error: sendErr.message,
      };
    }
  }

  // --- 3. Disabled / Unconfigured Mode ---
  if (isProduction) {
    console.warn('[EMAIL WARNING] Production email service is not configured. Reset email was not dispatched.');
  }
  return { success: false, mode: 'disabled' };
};
