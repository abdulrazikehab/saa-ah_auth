// apps/app-auth/src/email/email.service.ts
import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    console.log('🔧 EmailService initializing with:', {
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      user: process.env.SMTP_USER,
    });

    // Use environment variables for configuration
    this.transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.ethereal.email',
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    // Verify connection configuration
    this.verifyConnection();
  }

  private async verifyConnection() {
    try {
      await this.transporter.verify();
      console.log('✅ SMTP connection verified successfully');
    } catch (error) {
      console.error('❌ SMTP connection failed:', error);
    }
  }

  async sendPasswordResetEmail(email: string, code: string): Promise<{ messageId: string; previewUrl: string }> {
    const mailOptions = {
      from: '"E-Commerce Platform" <noreply@ecommerce.com>',
      to: email,
      subject: 'Password Reset Code',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
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
      console.log('📧 Attempting to send email to:', email);
      const info = await this.transporter.sendMail(mailOptions);
      
      console.log('✅ Password reset email sent successfully');
      console.log('📧 Message ID:', info.messageId);
      console.log('🔗 Preview URL:', nodemailer.getTestMessageUrl(info));

      return {
        messageId: info.messageId,
        previewUrl: nodemailer.getTestMessageUrl(info) || 'Check console for preview URL'
      };
    } catch (error) {
      console.error('❌ Failed to send email:', error);
      throw new Error(`Failed to send password reset email: ${error}`);
    }
  }
}