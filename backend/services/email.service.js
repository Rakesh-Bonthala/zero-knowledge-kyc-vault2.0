import nodemailer from 'nodemailer';
import { config } from '../config/config.js';

export class EmailService {
  static transporter = null;
  static isTestAccount = false;
  static lastDevPreviewUrl = null;
  static devOutbox = []; // In-memory queue for testing/dev inspection

  static async getTransporter() {
    if (this.transporter) {
      return this.transporter;
    }

    if (config.email.smtpHost && config.email.smtpUser) {
      this.transporter = nodemailer.createTransport({
        host: config.email.smtpHost,
        port: config.email.smtpPort,
        secure: config.email.smtpPort === 465,
        auth: {
          user: config.email.smtpUser,
          pass: config.email.smtpPass
        }
      });
      this.isTestAccount = false;
    } else {
      // Create Ethereal test inbox for development
      const testAccount = await nodemailer.createTestAccount();
      this.transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass
        }
      });
      this.isTestAccount = true;
    }

    return this.transporter;
  }

  /**
   * Dispatches OTP email.
   * NOTE: The raw OTP is NEVER logged to stdout/stderr.
   */
  static async sendOtpEmail(toEmail, otp, purpose) {
    const transporter = await this.getTransporter();

    let subject = 'Your Zero-Knowledge Vault Verification Code';
    let actionText = 'complete your action';

    if (purpose === 'register') {
      subject = 'Verify Your Registration — Zero-Knowledge KYC Vault';
      actionText = 'complete your account registration';
    } else if (purpose === 'login') {
      subject = 'Login Verification Code — Zero-Knowledge KYC Vault';
      actionText = 'authenticate your login attempt';
    } else if (purpose === 'reset') {
      subject = 'Password Reset Code — Zero-Knowledge KYC Vault';
      actionText = 'reset your account password';
    }

    const htmlContent = `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0a0e17; color: #f1f5f9; padding: 2rem; border-radius: 8px;">
        <h2 style="color: #06b6d4; margin-top: 0;">Zero-Knowledge KYC Vault</h2>
        <p style="color: #94a3b8;">Use the one-time verification code below to ${actionText}:</p>
        <div style="background-color: #162032; border: 1px solid #27354f; border-radius: 6px; padding: 1.25rem; text-align: center; margin: 1.5rem 0;">
          <span style="font-family: monospace; font-size: 2rem; font-weight: bold; letter-spacing: 0.35em; color: #34d399;">${otp}</span>
        </div>
        <p style="font-size: 0.85rem; color: #64748b;">This code is valid for 5 minutes and single-use only. If you did not request this code, please ignore this email.</p>
        <p style="font-size: 0.75rem; color: #475569; margin-top: 1.5rem; border-top: 1px solid #1f2d44; padding-top: 0.75rem;">Security Notice: Vault administrators will never ask for your verification code or your Client Encryption Passphrase.</p>
      </div>
    `;

    const info = await transporter.sendMail({
      from: `"Zero-Knowledge Vault" <${config.email.fromAddress}>`,
      to: toEmail,
      subject,
      text: `Your Zero-Knowledge KYC Vault verification code is: ${otp}. It expires in 5 minutes.`,
      html: htmlContent
    });

    if (this.isTestAccount) {
      this.lastDevPreviewUrl = nodemailer.getTestMessageUrl(info);
      this.devOutbox.push({
        to: toEmail,
        purpose,
        previewUrl: this.lastDevPreviewUrl,
        sentAt: new Date()
      });
      // Limit in-memory dev outbox history
      if (this.devOutbox.length > 50) this.devOutbox.shift();
    }

    return {
      messageId: info.messageId,
      previewUrl: this.lastDevPreviewUrl
    };
  }

  /**
   * Dispatches password changed confirmation email.
   */
  static async sendPasswordChangedNotification(toEmail) {
    const transporter = await this.getTransporter();

    await transporter.sendMail({
      from: `"Zero-Knowledge Vault" <${config.email.fromAddress}>`,
      to: toEmail,
      subject: 'Security Alert: Password Changed — Zero-Knowledge KYC Vault',
      text: 'Your password was recently changed. If you did not make this change, please contact support immediately.',
      html: `
        <div style="font-family: sans-serif; background-color: #0a0e17; color: #f1f5f9; padding: 2rem;">
          <h2 style="color: #fbbf24;">Password Changed Successfully</h2>
          <p style="color: #94a3b8;">The password for your Zero-Knowledge KYC Vault account was recently updated.</p>
          <p style="font-size: 0.85rem; color: #64748b;">All other active sessions have been terminated. Note that this change applies only to your login password; your Client Encryption Passphrase is unchanged.</p>
        </div>
      `
    });
  }
}

