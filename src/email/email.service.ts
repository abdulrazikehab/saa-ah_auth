// apps/app-auth/src/email/email.service.ts
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService implements OnModuleInit {
  private readonly logger = new Logger(EmailService.name);
  private transporter!: nodemailer.Transporter; // Will be initialized in initializeTransporter
  private isTestAccount: boolean = false;
  private testAccountCredentials: any = null;
  private initializationPromise: Promise<void>;

  constructor() {
    // Start initialization immediately but don't block constructor
    this.initializationPromise = this.initializeTransporter();
  }

  async onModuleInit() {
    // Wait for initialization to complete when module is ready
    await this.initializationPromise;
  }

  private async initializeTransporter() {
    // Use environment variables for configuration
    // Support Gmail and other SMTP providers
    const smtpHost = process.env.SMTP_HOST;
    const smtpPort = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : undefined;
    const smtpUser = process.env.SMTP_USER;
    const smtpPass = process.env.SMTP_PASS;
    const isGmail = smtpHost?.includes('gmail.com') || false;
    
    // Log configuration (without password)
    this.logger.log(`📧 Email service initializing...`);
    
    // If SMTP credentials are provided, try to use them, but fallback to test account if they fail
    if (smtpUser && smtpPass) {
      this.logger.log(`📧 Attempting to configure Gmail SMTP with user: ${smtpUser}`);
      try {
        // Always use Gmail service configuration for Gmail
        this.transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: {
            user: smtpUser,
            pass: smtpPass, // Gmail App Password (16 characters, no spaces)
          },
        });
        this.logger.log(`✅ Gmail transporter created with user: ${smtpUser.substring(0, 3)}***`);
        
        // Verify connection configuration - CRITICAL for real email delivery
        this.logger.log(`📧 Verifying Gmail SMTP connection...`);
        const verified = await this.verifyConnection();
        
        if (!verified) {
          // Don't silently fallback - throw error to force fixing Gmail credentials
          this.logger.error('❌ ========================================');
          this.logger.error('❌ GMAIL SMTP VERIFICATION FAILED!');
          this.logger.error('❌ Emails will NOT be sent to real inboxes!');
          this.logger.error('❌ ========================================');
          this.logger.error('❌ Your Gmail App Password is invalid or expired.');
          this.logger.error('❌ FIX IT NOW:');
          this.logger.error('❌ 1. Go to: https://myaccount.google.com/apppasswords');
          this.logger.error('❌ 2. Sign in with: ' + smtpUser);
          this.logger.error('❌ 3. Generate NEW App Password for "Mail"');
          this.logger.error('❌ 4. Copy 16-character password (remove spaces)');
          this.logger.error('❌ 5. Update SMTP_PASS in .env file');
          this.logger.error('❌ 6. Restart server');
          this.logger.error('❌ ========================================');
          
          // Only use test account in development mode
          if (process.env.NODE_ENV === 'development') {
            this.logger.warn('⚠️ Development mode: Using test account (emails go to preview URL only)');
            await this.createTestAccount();
          } else {
            // In production, fail hard
            throw new Error('Gmail SMTP verification failed. Real emails cannot be sent. Please fix SMTP_PASS in .env file.');
          }
        } else {
          this.isTestAccount = false; // Mark as real SMTP
          this.logger.log(`✅ Gmail SMTP verified! Real emails will be sent to user inboxes.`);
        }
      } catch (error) {
        this.logger.error(`❌ Failed to configure Gmail SMTP: ${error instanceof Error ? error.message : String(error)}`);
        if (error instanceof Error && error.message.includes('Invalid login')) {
          this.logger.error('❌ Gmail authentication failed - App Password is invalid');
        }
        this.logger.warn('⚠️ Falling back to test account (Ethereal.email) - emails will NOT go to real inboxes');
        await this.createTestAccount();
      }
    } else {
      // No SMTP credentials - automatically create test account
      this.logger.warn('⚠️ SMTP credentials not configured in .env file');
      this.logger.warn('⚠️ Creating test account (Ethereal.email) - emails will NOT go to real inboxes');
      await this.createTestAccount();
    }
  }

  private async createTestAccount() {
    try {
      this.logger.log('📧 Creating Ethereal.email test account...');
      // Create a test account using nodemailer's built-in test account generator
      const testAccount = await nodemailer.createTestAccount();
      this.testAccountCredentials = testAccount;
      
      this.transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false, // true for 465, false for other ports
        auth: {
          user: testAccount.user,
          pass: testAccount.pass,
        },
      });
      
      this.isTestAccount = true;
      this.logger.log('✅ Test email account created successfully (Ethereal.email)');
      this.logger.log(`📧 Test account email: ${testAccount.user}`);
      this.logger.log(`📧 Test account password: ${testAccount.pass}`);
      this.logger.warn('⚠️ Using test email service - emails will NOT be delivered to real inboxes');
      this.logger.warn('⚠️ Use preview URL to view emails or configure real Gmail SMTP for production');
      
      // Verify connection
      const verified = await this.verifyConnection();
      if (!verified) {
        throw new Error('Failed to verify test account connection');
      }
    } catch (error) {
      this.logger.error('❌ Failed to create test account:', error);
      this.logger.error(`Error details: ${error instanceof Error ? error.message : String(error)}`);
      // Try one more time
      try {
        this.logger.log('📧 Retrying test account creation...');
        const testAccount = await nodemailer.createTestAccount();
        this.testAccountCredentials = testAccount;
        
        this.transporter = nodemailer.createTransport({
          host: 'smtp.ethereal.email',
          port: 587,
          secure: false,
          auth: {
            user: testAccount.user,
            pass: testAccount.pass,
          },
        });
        
        this.isTestAccount = true;
        this.logger.log('✅ Test account created on retry');
        await this.verifyConnection();
      } catch (retryError) {
        this.logger.error('❌ Failed to create test account after retry:', retryError);
        // Last resort: use JSON transport (emails logged only)
        this.transporter = nodemailer.createTransport({
          jsonTransport: true,
        });
        this.logger.warn('⚠️ Using JSON transport - emails will be logged in console only');
      }
    }
  }

  private async verifyConnection(): Promise<boolean> {
    try {
      this.logger.log('📧 Verifying SMTP connection...');
      
      // CPU Safety: Add timeout to verification to prevent hanging
      const VERIFY_TIMEOUT_MS = 5000; // 5 seconds for verification
      await Promise.race([
        this.transporter.verify(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('SMTP verification timeout')), VERIFY_TIMEOUT_MS)
        )
      ]);
      
      this.logger.log('✅ SMTP connection verified successfully');
      return true;
    } catch (error: any) {
      this.logger.error('❌ ========================================');
      this.logger.error('❌ SMTP CONNECTION VERIFICATION FAILED');
      this.logger.error('❌ ========================================');
      
      if (error instanceof Error) {
        const errorCode = (error as any).code || 'N/A';
        const errorMessage = error.message;
        
        this.logger.error(`Error code: ${errorCode}`);
        this.logger.error(`Error message: ${errorMessage}`);
        
        // Provide specific help for Gmail errors
        if (errorCode === 'EAUTH' || errorMessage.includes('Invalid login') || errorMessage.includes('authentication failed')) {
          this.logger.error('❌ ========================================');
          this.logger.error('❌ GMAIL AUTHENTICATION FAILED!');
          this.logger.error('❌ The App Password is INCORRECT or EXPIRED');
          this.logger.error('❌ ========================================');
          this.logger.error('❌ TO FIX THIS:');
          this.logger.error('❌ 1. Go to: https://myaccount.google.com/apppasswords');
          this.logger.error('❌ 2. Sign in with: crunchy.helpdesk.team@gmail.com');
          this.logger.error('❌ 3. Make sure 2-Step Verification is ENABLED');
          this.logger.error('❌ 4. Click "Select app" → Choose "Mail"');
          this.logger.error('❌ 5. Click "Select device" → Choose "Other" → Type "Server"');
          this.logger.error('❌ 6. Click "Generate"');
          this.logger.error('❌ 7. Copy the 16-character password (like: abcd efgh ijkl mnop)');
          this.logger.error('❌ 8. REMOVE SPACES and update SMTP_PASS in .env');
          this.logger.error('❌ 9. Restart the server');
          this.logger.error('❌ ========================================');
        } else if (errorCode === 'ECONNECTION') {
          this.logger.error('❌ Connection error - check your internet connection');
        } else {
          this.logger.error('❌ Unknown error - check server logs for details');
        }
      } else {
        this.logger.error(`Unexpected error: ${String(error)}`);
      }
      
      this.logger.error('❌ ========================================');
      
      if (!this.isTestAccount) {
        this.logger.warn('⚠️ Email sending will fail until SMTP is properly configured');
      }
      return false;
    }
  }

  async sendPasswordResetEmail(email: string, code: string): Promise<{ messageId: string; previewUrl: string }> {
    // Ensure transporter is initialized
    await this.initializationPromise;
    
    // CPU Safety: Add timeout protection
    const EMAIL_TIMEOUT_MS = 10000; // 10 seconds max

    let fromEmail: string;
    let fromName: string;
    
    if (this.isTestAccount && this.testAccountCredentials) {
      fromEmail = this.testAccountCredentials.user;
      fromName = process.env.SMTP_FROM_NAME || 'Saeaa (Test)';
    } else {
      fromEmail = process.env.SMTP_FROM || process.env.SMTP_USER || 'noreply@saeaa.com';
      fromName = process.env.SMTP_FROM_NAME || 'Saeaa';
    }
    
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
      // CPU Safety: Add timeout to prevent hanging
      const sendEmailWithTimeout = Promise.race([
        this.transporter.sendMail(mailOptions),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Email sending timeout')), EMAIL_TIMEOUT_MS)
        )
      ]);
      
      const info: any = await sendEmailWithTimeout;
      this.logger.log(`Password reset email sent successfully to ${email}, Message ID: ${info.messageId}`);
      
      return {
        messageId: info.messageId,
        previewUrl: nodemailer.getTestMessageUrl(info) || ''
      };
    } catch (error: any) {
      this.logger.error(`Failed to send email to ${email}:`, error);
      // Provide more helpful error messages
      if ((error as any).code === 'EAUTH') {
        throw new Error('Email authentication failed. Please check SMTP credentials.');
      } else if ((error as any).code === 'ECONNECTION') {
        throw new Error('Failed to connect to SMTP server. Please check SMTP settings.');
      }
      throw new Error(`Failed to send password reset email: ${error.message || error}`);
    }
  }

  async sendPasswordResetLinkEmail(email: string, token: string): Promise<{ messageId: string; previewUrl: string }> {
    // Ensure transporter is initialized
    await this.initializationPromise;
    
    // CPU Safety: Add timeout protection
    const EMAIL_TIMEOUT_MS = 10000; // 10 seconds max

    let fromEmail: string;
    let fromName: string;
    
    if (this.isTestAccount && this.testAccountCredentials) {
      fromEmail = this.testAccountCredentials.user;
      fromName = process.env.SMTP_FROM_NAME || 'Saeaa (Test)';
    } else {
      fromEmail = process.env.SMTP_FROM || process.env.SMTP_USER || 'noreply@saeaa.com';
      fromName = process.env.SMTP_FROM_NAME || 'Saeaa';
    }

    // Build reset link - always use main domain for password reset (not tenant subdomain)
    // For password reset, users should access from main domain (localhost, saeaa.com, etc.)
    let frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    
    // Ensure we're not using backend port (3001, 3002) - use frontend port instead
    // Backend ports: 3001 (auth), 3002 (core)
    // Frontend ports: 3000, 5173 (Vite default)
    const urlObj = new URL(frontendUrl);
    const port = urlObj.port;
    
    if (port === '3001' || port === '3002') {
      // Replace backend ports with frontend default port (5173 for Vite dev server)
      urlObj.port = '5173';
      frontendUrl = urlObj.toString();
      this.logger.warn(`⚠️ Frontend URL was using backend port (${port}), corrected to: ${frontendUrl}`);
    } else if (!port || port === '' || port === '80' || port === '443') {
      // If no port specified or default HTTP/HTTPS ports, use frontend default
      if (urlObj.protocol === 'http:') {
        urlObj.port = '5173';
        frontendUrl = urlObj.toString();
      }
    }
    
    // For password reset, always use main domain (not tenant subdomain)
    // This ensures the reset link works regardless of which tenant the user belongs to
    const resetLink = `${frontendUrl}/auth/reset-password?token=${token}`;
    
    // Logo URL
    const logoUrl = process.env.EMAIL_LOGO_URL || 'https://via.placeholder.com/200x60/1E293B/06B6D4?text=Saeaa';
    
    const mailOptions = {
      from: `"${fromName}" <${fromEmail}>`,
      to: email,
      subject: 'إعادة تعيين كلمة المرور - Saeaa',
      html: `
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; font-family: 'Cairo', 'Segoe UI', Tahoma, Arial, sans-serif; background-color: #f8fafc;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f8fafc; padding: 20px 0;">
            <tr>
              <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                  <!-- Header with Logo -->
                  <tr>
                    <td style="background: linear-gradient(135deg, #1E293B 0%, #0f172a 100%); padding: 30px 20px; text-align: center;">
                      <img src="${logoUrl}" alt="Saeaa Logo" style="max-width: 180px; height: auto; margin-bottom: 10px;" />
                      <h1 style="color: #ffffff; margin: 10px 0 0 0; font-size: 28px; font-weight: 700;">سِعَة</h1>
                      <p style="color: #06B6D4; margin: 5px 0 0 0; font-size: 14px; font-weight: 500;">منصتك للتجارة الإلكترونية</p>
                    </td>
                  </tr>
                  
                  <!-- Main Content -->
                  <tr>
                    <td style="padding: 40px 30px;">
                      <h2 style="color: #1E293B; margin: 0 0 20px 0; font-size: 24px; font-weight: 700; text-align: right;">
                        طلب إعادة تعيين كلمة المرور
                      </h2>
                      
                      <p style="color: #475569; margin: 0 0 25px 0; font-size: 16px; line-height: 1.6; text-align: right;">
                        مرحباً،<br>
                        لقد تلقينا طلباً لإعادة تعيين كلمة المرور لحسابك. إذا كنت أنت من طلب ذلك، انقر على الزر أدناه لإعادة تعيين كلمة المرور.
                      </p>
                      
                      <!-- Reset Button -->
                      <table width="100%" cellpadding="0" cellspacing="0" style="margin: 30px 0;">
                        <tr>
                          <td align="center">
                            <a href="${resetLink}" style="display: inline-block; background: linear-gradient(135deg, #06B6D4 0%, #0891b2 100%); color: #ffffff; text-decoration: none; padding: 16px 40px; border-radius: 8px; font-weight: 600; font-size: 16px; box-shadow: 0 4px 6px rgba(6, 182, 212, 0.3);">
                              إعادة تعيين كلمة المرور
                            </a>
                          </td>
                        </tr>
                      </table>
                      
                      <p style="color: #64748b; margin: 25px 0 0 0; font-size: 14px; line-height: 1.6; text-align: right;">
                        أو انسخ والصق هذا الرابط في متصفحك:<br>
                        <a href="${resetLink}" style="color: #06B6D4; word-break: break-all; font-size: 12px;">${resetLink}</a>
                      </p>
                      
                      <div style="background-color: #fef3c7; border-right: 4px solid #f59e0b; padding: 15px; border-radius: 8px; margin: 25px 0;">
                        <p style="color: #92400e; margin: 0; font-size: 13px; text-align: right;">
                          <strong>⏰ مهم:</strong> هذا الرابط صالح لمدة ساعة واحدة فقط. إذا لم تطلب إعادة تعيين كلمة المرور، يمكنك تجاهل هذا البريد الإلكتروني بأمان.
                        </p>
                      </div>
                      
                      <p style="color: #64748b; margin: 25px 0 0 0; font-size: 14px; line-height: 1.6; text-align: right;">
                        إذا كنت تواجه مشكلة في النقر على الزر، انسخ والصق الرابط أعلاه في متصفح الويب الخاص بك.
                      </p>
                      
                      <p style="color: #94a3b8; margin: 25px 0 0 0; font-size: 13px; line-height: 1.6; text-align: right;">
                        إذا لم تطلب إعادة تعيين كلمة المرور، لا تقم بأي إجراء. حسابك آمن ولم يتم تغييره.
                      </p>
                    </td>
                  </tr>
                  
                  <!-- Footer -->
                  <tr>
                    <td style="background-color: #f1f5f9; padding: 25px 30px; text-align: center; border-top: 1px solid #e2e8f0;">
                      <p style="color: #64748b; margin: 0 0 10px 0; font-size: 13px; line-height: 1.6;">
                        <strong style="color: #1E293B;">Saeaa</strong> - منصتك الشاملة للتجارة الإلكترونية
                      </p>
                      <p style="color: #94a3b8; margin: 0; font-size: 12px;">
                        © ${new Date().getFullYear()} Saeaa. جميع الحقوق محفوظة.
                      </p>
                      <div style="margin-top: 20px;">
                        <a href="#" style="color: #06B6D4; text-decoration: none; margin: 0 10px; font-size: 13px;">الموقع الإلكتروني</a>
                        <span style="color: #cbd5e1;">|</span>
                        <a href="#" style="color: #06B6D4; text-decoration: none; margin: 0 10px; font-size: 13px;">الدعم</a>
                        <span style="color: #cbd5e1;">|</span>
                        <a href="#" style="color: #06B6D4; text-decoration: none; margin: 0 10px; font-size: 13px;">سياسة الخصوصية</a>
                      </div>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
      `,
    };

    try {
      this.logger.log(`📧 ========================================`);
      this.logger.log(`📧 SENDING PASSWORD RESET LINK EMAIL`);
      this.logger.log(`📧 Recipient: ${email}`);
      this.logger.log(`📧 FRONTEND_URL from env: ${process.env.FRONTEND_URL || 'NOT SET'}`);
      this.logger.log(`📧 Frontend URL used: ${frontendUrl}`);
      this.logger.log(`📧 Reset Link: ${resetLink}`);
      this.logger.log(`📧 Service: ${this.isTestAccount ? 'Ethereal Test (preview only)' : 'Real SMTP (Gmail)'}`);
      this.logger.log(`📧 ========================================`);
      
      // CPU Safety: Add timeout to prevent hanging
      const sendEmailWithTimeout = Promise.race([
        this.transporter.sendMail(mailOptions),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Email sending timeout')), EMAIL_TIMEOUT_MS)
        )
      ]);
      
      const info: any = await sendEmailWithTimeout;
      this.logger.log(`✅ Email sent! Message ID: ${info.messageId}`);
      
      const previewUrl = nodemailer.getTestMessageUrl(info);
      
      if (previewUrl || this.isTestAccount) {
        this.logger.error(`❌ ========================================`);
        this.logger.error(`❌ ⚠️ USING TEST EMAIL SERVICE (Ethereal.email)`);
        this.logger.error(`❌ ⚠️ EMAIL WAS NOT SENT TO REAL INBOX: ${email}`);
        this.logger.error(`❌ Reset Link: ${resetLink}`);
        this.logger.error(`❌ Preview URL: ${previewUrl || 'N/A'}`);
        this.logger.error(`❌ ========================================`);
        
        if (previewUrl) {
          this.logger.warn(`🔗 Preview URL (emails don't go to real inbox): ${previewUrl}`);
        }
      } else {
        this.logger.log(`✅ ========================================`);
        this.logger.log(`✅ EMAIL SENT TO REAL INBOX: ${email}`);
        this.logger.log(`✅ User should check their Gmail inbox for reset link`);
        this.logger.log(`✅ ========================================`);
      }
      
      return {
        messageId: info.messageId || 'test',
        previewUrl: previewUrl || '',
      };
    } catch (error: any) {
      this.logger.error(`❌ Failed to send password reset link email to ${email}:`, error);
      this.logger.error(`Error details - Code: ${(error as any).code}, Message: ${error.message}`);
      
      if ((error as any).code === 'EAUTH') {
        throw new Error('Email authentication failed. Please check SMTP credentials.');
      } else if ((error as any).code === 'ECONNECTION') {
        throw new Error('Failed to connect to SMTP server. Please check SMTP settings.');
      }
      throw new Error(`Failed to send password reset link email: ${error.message || error}`);
    }
  }

  async sendVerificationEmail(email: string, code: string): Promise<{ messageId: string; previewUrl: string; isTestEmail?: boolean; code?: string }> {
    // Ensure transporter is initialized
    await this.initializationPromise;

    // CPU Safety: Add timeout protection to prevent hanging
    const EMAIL_TIMEOUT_MS = 10000; // 10 seconds max
    const MAX_RETRIES = 1; // Only retry once to prevent CPU loops

    // Determine from email and name
    let fromEmail: string;
    let fromName: string;
    
    if (this.isTestAccount && this.testAccountCredentials) {
      // Use test account email for test emails
      fromEmail = this.testAccountCredentials.user;
      fromName = process.env.SMTP_FROM_NAME || 'Saeaa (Test)';
    } else {
      fromEmail = process.env.SMTP_FROM || process.env.SMTP_USER || 'noreply@saeaa.com';
      fromName = process.env.SMTP_FROM_NAME || 'Saeaa';
    }
    
    // Logo URL - you can replace this with your actual logo URL
    const logoUrl = process.env.EMAIL_LOGO_URL || 'https://via.placeholder.com/200x60/1E293B/06B6D4?text=Saeaa';
    
    const mailOptions = {
      from: `"${fromName}" <${fromEmail}>`,
      to: email, // IMPORTANT: This sends to the user's actual email address
      subject: 'رمز التحقق من البريد الإلكتروني - Saeaa',
      html: `
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; font-family: 'Cairo', 'Segoe UI', Tahoma, Arial, sans-serif; background-color: #f8fafc;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f8fafc; padding: 20px 0;">
            <tr>
              <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                  <!-- Header with Logo -->
                  <tr>
                    <td style="background: linear-gradient(135deg, #1E293B 0%, #0f172a 100%); padding: 30px 20px; text-align: center;">
                      <img src="${logoUrl}" alt="Saeaa Logo" style="max-width: 180px; height: auto; margin-bottom: 10px;" />
                      <h1 style="color: #ffffff; margin: 10px 0 0 0; font-size: 28px; font-weight: 700;">سِعَة</h1>
                      <p style="color: #06B6D4; margin: 5px 0 0 0; font-size: 14px; font-weight: 500;">منصتك للتجارة الإلكترونية</p>
                    </td>
                  </tr>
                  
                  <!-- Main Content -->
                  <tr>
                    <td style="padding: 40px 30px;">
                      <h2 style="color: #1E293B; margin: 0 0 20px 0; font-size: 24px; font-weight: 700; text-align: right;">
                        مرحباً بك في Saeaa! 🎉
                      </h2>
                      
                      <p style="color: #475569; margin: 0 0 25px 0; font-size: 16px; line-height: 1.6; text-align: right;">
                        نشكرك على التسجيل في منصة Saeaa. لاستكمال عملية التسجيل، يرجى التحقق من عنوان بريدك الإلكتروني باستخدام الرمز أدناه:
                      </p>
                      
                      <!-- Verification Code Box -->
                      <div style="background: linear-gradient(135deg, #06B6D4 0%, #0891b2 100%); border-radius: 10px; padding: 30px; text-align: center; margin: 30px 0;">
                        <p style="color: #ffffff; margin: 0 0 10px 0; font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">
                          رمز التحقق
                        </p>
                        <div style="background-color: #ffffff; border-radius: 8px; padding: 20px; margin: 15px auto; display: inline-block;">
                          <p style="color: #1E293B; margin: 0; font-size: 36px; font-weight: 700; letter-spacing: 8px; font-family: 'Courier New', monospace;">
                            ${code}
                          </p>
                        </div>
                        <p style="color: #ffffff; margin: 15px 0 0 0; font-size: 13px; opacity: 0.9;">
                          صالح لمدة 15 دقيقة
                        </p>
                      </div>
                      
                      <p style="color: #64748b; margin: 25px 0 0 0; font-size: 14px; line-height: 1.6; text-align: right;">
                        إذا لم تقم بإنشاء حساب، يرجى تجاهل هذا البريد الإلكتروني.
                      </p>
                      
                      <!-- CTA Button -->
                      <table width="100%" cellpadding="0" cellspacing="0" style="margin: 30px 0;">
                        <tr>
                          <td align="center">
                            <a href="https://saeaa.com" style="display: inline-block; background-color: #1E293B; color: #ffffff; text-decoration: none; padding: 14px 40px; border-radius: 8px; font-weight: 600; font-size: 16px;">
                              ابدأ رحلتك معنا
                            </a>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                  
                  <!-- Footer -->
                  <tr>
                    <td style="background-color: #f1f5f9; padding: 25px 30px; text-align: center; border-top: 1px solid #e2e8f0;">
                      <p style="color: #64748b; margin: 0 0 10px 0; font-size: 13px; line-height: 1.6;">
                        <strong style="color: #1E293B;">Saeaa</strong> - منصتك الشاملة للتجارة الإلكترونية
                      </p>
                      <p style="color: #94a3b8; margin: 0; font-size: 12px;">
                        © ${new Date().getFullYear()} Saeaa. جميع الحقوق محفوظة.
                      </p>
                      <div style="margin-top: 20px;">
                        <a href="#" style="color: #06B6D4; text-decoration: none; margin: 0 10px; font-size: 13px;">الموقع الإلكتروني</a>
                        <span style="color: #cbd5e1;">|</span>
                        <a href="#" style="color: #06B6D4; text-decoration: none; margin: 0 10px; font-size: 13px;">الدعم</a>
                        <span style="color: #cbd5e1;">|</span>
                        <a href="#" style="color: #06B6D4; text-decoration: none; margin: 0 10px; font-size: 13px;">سياسة الخصوصية</a>
                      </div>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
      `,
    };

    try {
      this.logger.log(`📧 ========================================`);
      this.logger.log(`📧 SENDING VERIFICATION EMAIL`);
      this.logger.log(`📧 Recipient: ${email}`);
      this.logger.log(`📧 Verification Code: ${code}`);
      this.logger.log(`📧 Service: ${this.isTestAccount ? 'Ethereal Test (preview only)' : 'Real SMTP (Gmail)'}`);
      this.logger.log(`📧 ========================================`);
      
      // Ensure transporter is initialized
      if (!this.transporter) {
        this.logger.error('❌ Email transporter not initialized!');
        throw new Error('Email transporter not initialized. Please restart the server.');
      }
      
      // CPU Safety: Add timeout to prevent hanging and CPU spikes
      const sendEmailWithTimeout = async () => {
        return Promise.race([
          this.transporter.sendMail(mailOptions),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Email sending timeout - SMTP server not responding')), EMAIL_TIMEOUT_MS)
          )
        ]);
      };
      
      let info: any;
      try {
        info = await sendEmailWithTimeout();
      } catch (timeoutError: any) {
        if (timeoutError.message.includes('timeout')) {
          this.logger.error(`❌ Email sending timed out after ${EMAIL_TIMEOUT_MS}ms - stopping to prevent CPU issues`);
          // Don't retry on timeout - it will just waste CPU
          throw new Error('Email service timeout. Please check SMTP server connection.');
        }
        throw timeoutError;
      }
      this.logger.log(`✅ Email sent! Message ID: ${info.messageId}`);
      
      // Get preview URL if using test account
      const previewUrl = nodemailer.getTestMessageUrl(info);
      
      if (previewUrl || this.isTestAccount) {
        // Using test account - email NOT sent to real inbox
        this.logger.log(`📧 ========================================`);
        this.logger.log(`📧 ⚠️ TEST EMAIL SERVICE - Ethereal.email`);
        this.logger.log(`📧 ⚠️ EMAIL NOT SENT TO REAL INBOX: ${email}`);
        this.logger.log(`📧 Verification Code: ${code}`);
        this.logger.log(`📧 Email Preview URL: ${previewUrl || 'N/A'}`);
        this.logger.log(`📧 ========================================`);
        
        if (previewUrl) {
          this.logger.log(`🔗 OPEN THIS URL TO VIEW EMAIL: ${previewUrl}`);
        }
        
        this.logger.warn(`⚠️ To send real emails to ${email}, you need valid Gmail SMTP credentials`);
        this.logger.warn(`⚠️ Get Gmail App Password: https://myaccount.google.com/apppasswords`);
      } else {
        // Real email sent successfully to user's inbox
        this.logger.log(`✅ ========================================`);
        this.logger.log(`✅ Email delivered to REAL inbox: ${email}`);
        this.logger.log(`✅ User can check their Gmail inbox for verification code`);
        this.logger.log(`✅ ========================================`);
      }
      
      return {
        messageId: info.messageId || 'test',
        previewUrl: previewUrl || '',
        isTestEmail: this.isTestAccount || !!previewUrl,
        code: code, // Always return code for logging
      };
    } catch (error: any) {
      this.logger.error(`❌ Failed to send verification email to ${email}:`, error);
      this.logger.error(`Error details - Code: ${(error as any).code}, Message: ${error.message}`);
      
      if ((error as any).code === 'EAUTH') {
        // CPU Safety: Only retry once to prevent infinite loops
        // If using test account and still getting auth error, try recreating test account ONCE
        if (this.isTestAccount && MAX_RETRIES > 0) {
          this.logger.warn('⚠️ Test account authentication failed, attempting to recreate (one retry only)...');
          try {
            // CPU Safety: Add timeout to retry as well
            const recreateWithTimeout = Promise.race([
              this.createTestAccount(),
              new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Test account creation timeout')), 5000)
              )
            ]);
            
            await recreateWithTimeout;
            
            // Retry sending with timeout
            const retryWithTimeout = Promise.race([
              this.transporter.sendMail(mailOptions),
              new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Retry email sending timeout')), EMAIL_TIMEOUT_MS)
              )
            ]);
            
            const retryInfo: any = await retryWithTimeout;
            const retryPreviewUrl = nodemailer.getTestMessageUrl(retryInfo);
            this.logger.log(`✅ Email sent successfully after recreating test account`);
            return {
              messageId: retryInfo.messageId,
              previewUrl: retryPreviewUrl || '',
              isTestEmail: true,
            };
          } catch (retryError: any) {
            this.logger.error('❌ Failed to send email even after recreating test account - stopping retries to prevent CPU issues');
            // In development, don't throw - let the code be displayed
            if (process.env.NODE_ENV === 'development') {
              this.logger.warn(`⚠️ Development mode: Verification code is ${code} (email sending failed)`);
              return {
                messageId: 'test',
                previewUrl: '',
                isTestEmail: true,
              };
            }
            // Don't retry again - stop to prevent CPU loops
            throw new Error('Email service unavailable. Please try again later.');
          }
        }
        const errorMsg = 'Email authentication failed. Please check SMTP_USER and SMTP_PASS credentials, or the system will use a test account.';
        this.logger.error(errorMsg);
        throw new Error(errorMsg);
      } else if ((error as any).code === 'ECONNECTION') {
        const errorMsg = `Failed to connect to SMTP server. ${this.isTestAccount ? 'Test account connection failed.' : `Please check SMTP_HOST and SMTP_PORT settings.`}`;
        this.logger.error(errorMsg);
        // In development, don't throw - let the code be displayed
        if (process.env.NODE_ENV === 'development') {
          this.logger.warn(`⚠️ Development mode: Verification code is ${code} (email sending failed)`);
          return {
            messageId: 'test',
            previewUrl: '',
            isTestEmail: true,
          };
        }
        throw new Error(errorMsg);
      } else if ((error as any).code === 'EENVELOPE') {
        const errorMsg = `Invalid email address: ${email}`;
        this.logger.error(errorMsg);
        throw new Error(errorMsg);
      }
      // In development, don't throw - let the code be displayed
      if (process.env.NODE_ENV === 'development') {
        this.logger.warn(`⚠️ Development mode: Verification code is ${code} (email sending failed: ${error.message})`);
        return {
          messageId: 'test',
          previewUrl: '',
          isTestEmail: true,
        };
      }
      throw new Error(`Failed to send verification email: ${error.message || String(error)}`);
    }
  }

  async sendEmail(to: string, subject: string, html: string, text?: string): Promise<{ messageId: string; previewUrl: string }> {
    // Ensure transporter is initialized
    await this.initializationPromise;
    
    // CPU Safety: Add timeout protection
    const EMAIL_TIMEOUT_MS = 10000; // 10 seconds max

    let fromEmail: string;
    let fromName: string;
    
    if (this.isTestAccount && this.testAccountCredentials) {
      fromEmail = this.testAccountCredentials.user;
      fromName = process.env.SMTP_FROM_NAME || 'Saeaa (Test)';
    } else {
      fromEmail = process.env.SMTP_FROM || process.env.SMTP_USER || 'noreply@saeaa.com';
      fromName = process.env.SMTP_FROM_NAME || 'Saeaa';
    }
    
    const mailOptions = {
      from: `"${fromName}" <${fromEmail}>`,
      to,
      subject,
      html,
      text: text || html.replace(/<[^>]*>/g, ''), // Strip HTML for text version
    };

    try {
      // CPU Safety: Add timeout to prevent hanging
      const sendEmailWithTimeout = Promise.race([
        this.transporter.sendMail(mailOptions),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Email sending timeout')), EMAIL_TIMEOUT_MS)
        )
      ]);
      
      const info: any = await sendEmailWithTimeout;
      this.logger.log(`Email sent successfully to ${to}, Message ID: ${info.messageId}`);
      
      return {
        messageId: info.messageId,
        previewUrl: nodemailer.getTestMessageUrl(info) || ''
      };
    } catch (error: any) {
      this.logger.error(`Failed to send email to ${to}:`, error);
      if ((error as any).code === 'EAUTH') {
        throw new Error('Email authentication failed. Please check SMTP credentials.');
      } else if ((error as any).code === 'ECONNECTION') {
        throw new Error('Failed to connect to SMTP server. Please check SMTP settings.');
      }
      throw new Error(`Failed to send email: ${error.message || error}`);
    }
  }
}