// apps/app-auth/src/email/email.service.ts
import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;

  constructor() {
    // Use environment variables for configuration
    // Support Gmail and other SMTP providers
    const smtpHost = process.env.SMTP_HOST || 'smtp.gmail.com';
    const smtpPort = parseInt(process.env.SMTP_PORT || '587');
    const isGmail = smtpHost.includes('gmail.com');
    
    this.transporter = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort === 465, // true for 465, false for other ports
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS, // For Gmail, use App Password
      },
      // Gmail-specific settings
      ...(isGmail && {
        service: 'gmail',
        tls: {
          rejectUnauthorized: false, // Allow self-signed certificates
        },
      }),
    });

    // Verify connection configuration
    this.verifyConnection();
  }

  private async verifyConnection() {
    try {
      await this.transporter.verify();
      this.logger.log('SMTP connection verified successfully');
    } catch (error) {
      this.logger.error('SMTP connection failed: ' + error);
    }
  }

  async sendPasswordResetEmail(email: string, code: string): Promise<{ messageId: string; previewUrl: string }> {
    const fromEmail = process.env.SMTP_FROM || process.env.SMTP_USER || 'noreply@ecommerce.com';
    const fromName = process.env.SMTP_FROM_NAME || 'E-Commerce Platform';
    
    const mailOptions = {
      from: `"${fromName}" <${fromEmail}>`,
      to: email,
      subject: 'Password Reset Code',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #333;">Password Reset Request</h2>
          <p>You requested to reset your password. Use the code below to reset your password:</p>
          <div style="background: #f4f4f4; padding: 15px; border-radius: 5px; text-align: center; font-size: 24px; letter-spacing: 5px; margin: 20px 0;">
            <strong>${code}</strong>
          </div>
          <p>This code will expire in 15 minutes.</p>
          <p>If you didn't request this reset, please ignore this email.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
          <p style="color: #666; font-size: 12px;">E-Commerce Platform Team</p>
        </div>
      `,
    };

    try {
      const info = await this.transporter.sendMail(mailOptions);
      this.logger.log(`Password reset email sent successfully to ${email}, Message ID: ${info.messageId}`);
      
      return {
        messageId: info.messageId,
        previewUrl: nodemailer.getTestMessageUrl(info) || ''
      };
    } catch (error: any) {
      this.logger.error(`Failed to send email to ${email}:`, error);
      // Provide more helpful error messages
      if (error.code === 'EAUTH') {
        throw new Error('Email authentication failed. Please check SMTP credentials.');
      } else if (error.code === 'ECONNECTION') {
        throw new Error('Failed to connect to SMTP server. Please check SMTP settings.');
      }
      throw new Error(`Failed to send password reset email: ${error.message || error}`);
    }
  }

  async sendEmail(to: string, subject: string, html: string, text?: string): Promise<{ messageId: string; previewUrl: string }> {
    const fromEmail = process.env.SMTP_FROM || process.env.SMTP_USER || 'noreply@ecommerce.com';
    const fromName = process.env.SMTP_FROM_NAME || 'E-Commerce Platform';
    
    const mailOptions = {
      from: `"${fromName}" <${fromEmail}>`,
      to,
      subject,
      html,
      text: text || html.replace(/<[^>]*>/g, ''), // Strip HTML for text version
    };

    try {
      const info = await this.transporter.sendMail(mailOptions);
      this.logger.log(`Email sent successfully to ${to}, Message ID: ${info.messageId}`);
      
      return {
        messageId: info.messageId,
        previewUrl: nodemailer.getTestMessageUrl(info) || ''
      };
    } catch (error: any) {
      this.logger.error(`Failed to send email to ${to}:`, error);
      if (error.code === 'EAUTH') {
        throw new Error('Email authentication failed. Please check SMTP credentials.');
      } else if (error.code === 'ECONNECTION') {
        throw new Error('Failed to connect to SMTP server. Please check SMTP settings.');
      }
      throw new Error(`Failed to send email: ${error.message || error}`);
    }
  }
}