import { Injectable, UnauthorizedException, ConflictException, BadRequestException, ForbiddenException, Logger, NotFoundException, InternalServerErrorException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import { PrismaService } from '../../prisma/prisma.service';
import { EmailService } from '../../email/email.service';
import { RateLimitingService } from '../../rate-limiting/rate-limiting.service';
import { SignUpDto, SignUpResponseDto } from '../dto/signup.dto';
import { LoginDto, LoginResponseDto } from '../dto/login.dto';
import { ForgotPasswordDto, ResetPasswordDto } from '../dto/password.dto';
import { validateEmailWithMx, generateRecoveryId } from '../../utils/email-validator';
import { checkIpReputation } from '../../utils/ip-checker';
import { Prisma } from '@prisma/client';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private pendingSignups: Map<string, any> = new Map(); // Temporary storage for pending signups

  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
    private emailService: EmailService,
    private rateLimitingService: RateLimitingService,
  ) {}

  async testDatabaseConnection() {
    try {
      const userCount = await this.prismaService.user.count();
      this.logger.log('✅ Database connection test successful');
      return userCount;
    } catch (error) {
      this.logger.error('❌ Database connection test failed:', error);
      throw error;
    }
  }

  /**
   * Create a test security event for testing purposes
   */
  async createTestSecurityEvent(ipAddress: string, userAgent: string) {
    // Use a public IP for testing if localhost is passed
    const testIp = ipAddress.includes('127.0.0.1') || ipAddress.includes('::1') 
      ? '8.8.8.8' // Use Google's DNS IP for testing (will show as US)
      : ipAddress;

    this.logger.log(`🧪 Creating test security event with IP: ${testIp}, UA: ${userAgent}`);

    await this.logSecurityEvent(
      'SUCCESSFUL_LOGIN',
      'LOW',
      undefined,
      undefined,
      testIp,
      userAgent,
      'Test security event for development',
      { test: true }
    );

    return {
      ipAddress: testIp,
      userAgent: userAgent.substring(0, 50) + '...',
      timestamp: new Date().toISOString()
    };
  }

  async signUp(signUpDto: SignUpDto, fingerprint?: any): Promise<SignUpResponseDto> {
    const emailForError = signUpDto?.email || 'unknown';
    try {
      let { email, password, name, storeName, subdomain } = signUpDto;

      if (!email || !password) {
        throw new BadRequestException('Email and password are required');
      }

      // Validate email - check for fake/disposable emails
      const emailValidation = await validateEmailWithMx(email);
      if (!emailValidation.isValid) {
        this.logger.warn(`Signup attempted with invalid email: ${email} - ${emailValidation.reason}`);
        throw new BadRequestException(emailValidation.reason || 'Invalid email address');
      }

      // Check device fingerprint
      if (fingerprint) {
          await this.checkDeviceFingerprint(fingerprint, email, 'unknown');
      }

      // NO automatic store name or subdomain generation
      // User will create market manually via setup page after signup
      // We don't need storeName or subdomain during signup anymore

      // Check rate limiting for signup
      const signupConfig = this.rateLimitingService.getSignupConfig();
      const rateLimitCheck = await this.rateLimitingService.checkRateLimit(
        email,
        'REGISTRATION',
        signupConfig.maxAttempts,
        signupConfig.windowMs
      );

      if (!rateLimitCheck.allowed) {
        throw new ForbiddenException(`Too many signup attempts. Please try again after ${Math.ceil((rateLimitCheck.resetTime.getTime() - Date.now()) / 60000)} minutes.`);
      }

      // Check if user already exists
      const existingUser = await this.prismaService.user.findUnique({
        where: { email },
      });

    if (existingUser) {
      throw new ConflictException('User already exists');
    }

    // No need to check subdomain - user will create market manually

    // Check for existing pending signup
    const existingPending = await this.prismaService.passwordReset.findFirst({
      where: {
        email,
        used: false,
        expiresAt: {
          gt: new Date(),
        },
        code: {
          startsWith: 'SIGNUP_', // Mark signup OTPs with prefix
        },
      },
    });

    if (existingPending) {
      // Allow resending OTP by deleting the old pending signup and creating a new one
      this.logger.log(`Found existing pending signup for ${email}, cleaning up and allowing new signup...`);
      await this.prismaService.passwordReset.delete({
        where: { id: existingPending.id },
      });
      // Also clean up any old pending signup data from memory
      // Note: We can't delete from memory map easily, but it will be overwritten
    }

    // Generate OTP code (mark with SIGNUP_ prefix)
    const verificationCode = this.generateResetCode();
    const signupCode = `SIGNUP_${verificationCode}`;
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // Hash password before storing
    const hashedPassword = await bcrypt.hash(password, 12);

    // Store signup data temporarily in passwordReset table with signup data in code field
    // We'll store the signup data as JSON in the code field (along with the actual OTP)
    // Note: No storeName or subdomain - user will create market manually via setup page
    const signupData = {
      email,
      password: hashedPassword,
      name,
      fingerprint,
    };

    // Store in passwordReset table (using code field to store signup metadata)
    await this.prismaService.passwordReset.create({
      data: {
        email,
        code: signupCode, // Store signup code prefix + actual OTP
        expiresAt,
        // Store signup data as JSON in a way we can retrieve it
        // We'll store it by encoding in the email field or use metadata approach
        // For now, we'll store the actual OTP in code and use a lookup
      },
    });

    // Store signup data separately - we'll use email+code as key
    // Actually, let's store it in a simple in-memory cache for now
    // Or better: store signup data in the database with a reference
    // We can use a separate approach: store signup metadata temporarily
    // For simplicity, we'll store it in memory with email as key
    if (!this.pendingSignups) {
      this.pendingSignups = new Map();
    }
    this.pendingSignups.set(`${email}_${verificationCode}`, signupData);

    // Send verification email with the actual OTP (not the prefixed one)
    let emailSent = false;
    let emailError: any = null;
    let emailResult: any = null;
    
    try {
      this.logger.log(`📧 ========================================`);
      this.logger.log(`📧 SENDING OTP EMAIL`);
      this.logger.log(`📧 To: ${email}`);
      this.logger.log(`📧 Code: ${verificationCode}`);
      this.logger.log(`📧 ========================================`);
      
      emailResult = await this.emailService.sendVerificationEmail(email, verificationCode);
      
      this.logger.log(`✅ Email service returned successfully`);
      this.logger.log(`✅ Message ID: ${emailResult.messageId}`);
      this.logger.log(`✅ Is Test Email: ${emailResult.isTestEmail}`);
      
      if (emailResult.previewUrl) {
        this.logger.log(`🔗 PREVIEW URL: ${emailResult.previewUrl}`);
      }
      
      emailSent = true;
      
      // If using test email service (Ethereal), always log the preview URL and code
      if (emailResult.previewUrl || emailResult.isTestEmail) {
        this.logger.log(`📧 EMAIL PREVIEW URL: ${emailResult.previewUrl || 'Will be available after sending'}`);
        this.logger.warn(`⚠️ Using test email service (Ethereal). Verification code: ${verificationCode}`);
        if (emailResult.previewUrl) {
          this.logger.warn(`⚠️ Open this URL to see the email: ${emailResult.previewUrl}`);
        }
      } else {
        this.logger.log(`✅ Email sent to real inbox: ${email}`);
      }
    } catch (error) {
      emailError = error;
      this.logger.error('❌ Failed to send verification email:', error);
      this.logger.error(`Error details: ${error instanceof Error ? error.message : String(error)}`);
      
      // In development, allow signup to continue but return the code
      if (process.env.NODE_ENV === 'development') {
        this.logger.warn(`⚠️ Development mode: Email sending failed, but continuing with code: ${verificationCode}`);
        this.logger.warn(`⚠️ Error: ${error instanceof Error ? error.message : String(error)}`);
        this.logger.warn(`⚠️ User can still verify with code: ${verificationCode}`);
        emailSent = false; // Mark as not sent but continue
        // Don't clean up - allow user to verify with code
      } else {
        // In production, clean up and throw error to prevent account creation
        await this.prismaService.passwordReset.deleteMany({
          where: { email, code: signupCode },
        });
        this.pendingSignups.delete(`${email}_${verificationCode}`);
        throw new BadRequestException(`Failed to send verification email: ${error instanceof Error ? error.message : 'Unknown error'}. Please check SMTP configuration or try again later.`);
      }
    }
    
    // CRITICAL: Make absolutely sure NO user was created during signup process
    // This should never happen, but double-check for safety
    const userCreatedCheck = await this.prismaService.user.findUnique({
      where: { email },
    });
    
    if (userCreatedCheck) {
      this.logger.error(`🚨 CRITICAL ERROR: User ${userCreatedCheck.id} was created during signup without OTP!`);
      this.logger.error(`🚨 Deleting incorrectly created user: ${userCreatedCheck.id}`);
      // Delete the incorrectly created user
      try {
        await this.prismaService.user.delete({
          where: { email },
        });
        this.logger.log(`✅ Deleted incorrectly created user`);
      } catch (deleteError) {
        this.logger.error(`❌ Failed to delete incorrectly created user: ${deleteError}`);
      }
      // Clean up pending signup data
      await this.prismaService.passwordReset.deleteMany({
        where: { email, code: signupCode },
      });
      this.pendingSignups.delete(`${email}_${verificationCode}`);
      throw new InternalServerErrorException('An error occurred. Please try signing up again.');
    }

    this.logger.log(`📧 OTP sent for signup: ${email} (account will be created AFTER OTP verification)`);

    // IMPORTANT: NO USER OR TENANT IS CREATED YET!
    // User account will ONLY be created in verifySignupCode() after successful OTP verification
    // Return response indicating OTP was sent (NO account created yet)
    const response: any = {
      email,
      emailVerified: false,
      verificationCodeSent: emailSent,
      // DO NOT include: id, recoveryId, accessToken, refreshToken
      // These will only be returned after OTP verification in verifySignupCode()
    };

    // ALWAYS return the verification code in response (for development/testing)
    response.verificationCode = verificationCode;
    
    if (emailSent && emailResult) {
      if (emailResult.isTestEmail || emailResult.previewUrl) {
        response.emailPreviewUrl = emailResult.previewUrl;
        response.isTestEmail = true;
        response.emailWarning = 'Using test email service. Check preview URL or use code below.';
        this.logger.log(`📧 Test email - Code: ${verificationCode}, Preview: ${emailResult.previewUrl || 'N/A'}`);
      }
    }
    
    if (!emailSent && emailError) {
      response.emailError = emailError instanceof Error ? emailError.message : 'Email sending failed';
      response.emailWarning = 'Email sending failed, but you can use the code above to verify.';
    }
    
    this.logger.log(`✅ Signup completed for: ${email} - NO USER CREATED (waiting for OTP verification)`);
    this.logger.log(`📋 OTP Code: ${verificationCode} (user must verify before account creation)`);
    this.logger.log(`📋 Response: verificationCodeSent=${emailSent}, hasCode=${!!response.verificationCode}`);
    
    return response;
    } catch (error: any) {
      this.logger.error(`❌ Error in signUp method for ${emailForError}:`, error);
      this.logger.error(`Error stack: ${error?.stack || 'No stack trace'}`);
      if (error && typeof error === 'object') {
        try {
          this.logger.error(`Error details: ${JSON.stringify(error, Object.getOwnPropertyNames(error))}`);
        } catch (e) {
          this.logger.error(`Error message: ${error?.message || String(error)}`);
        }
      }
      
      // Re-throw known exceptions
      if (error instanceof BadRequestException || 
          error instanceof ConflictException || 
          error instanceof ForbiddenException) {
        throw error;
      }
      
      // Wrap unknown errors
      throw new InternalServerErrorException(`Signup failed: ${error?.message || 'Unknown error'}`);
    }
  }

  async verifySignupCode(email: string, code: string): Promise<{ valid: boolean; message: string; tokens?: any; recoveryId?: string }> {
    // Find the signup verification code (with SIGNUP_ prefix)
    const signupCode = `SIGNUP_${code}`;
    const resetRecord = await this.prismaService.passwordReset.findFirst({
      where: {
        email,
        code: signupCode,
        used: false,
        expiresAt: {
          gt: new Date(), // Not expired
        },
      },
    });

    if (!resetRecord) {
      await this.logSecurityEvent(
        'INVALID_VERIFICATION_CODE',
        'LOW',
        undefined,
        undefined,
        undefined,
        undefined,
        `Invalid verification code attempt for email: ${email}`
      );
      return {
        valid: false,
        message: 'Invalid or expired verification code',
      };
    }

    // Get signup data from memory
    const signupDataKey = `${email}_${code}`;
    const signupData = this.pendingSignups.get(signupDataKey);

    if (!signupData) {
      this.logger.error(`Signup data not found for: ${email}_${code}`);
      return {
        valid: false,
        message: 'Signup session expired. Please sign up again.',
      };
    }

    // Re-check if user already exists (race condition protection)
    const existingUser = await this.prismaService.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      // Clean up and return error
      await this.prismaService.passwordReset.update({
        where: { id: resetRecord.id },
        data: { used: true },
      });
      this.pendingSignups.delete(signupDataKey);
      throw new ConflictException('User already exists');
    }

    // No need to check subdomain - user will create market manually via setup page
    // Generate recovery ID
    const recoveryId = generateRecoveryId();

    // ============================================================
    // NOW CREATE THE USER ACCOUNT (ONLY after successful OTP verification)
    // This is the ONLY place where user is created during signup
    // NO tenant is created - user must create market manually via setup page
    // No user exists in database until this point!
    // ============================================================
    this.logger.log(`🔐 Creating user account for ${email} AFTER successful OTP verification (no tenant - user must set up market)`);
    
    // Final check: Make absolutely sure user doesn't exist yet
    const finalUserCheck = await this.prismaService.user.findUnique({
      where: { email },
    });
    
    if (finalUserCheck) {
      this.logger.error(`❌ User already exists for ${email} - this should not happen!`);
      throw new ConflictException('User already exists. Cannot create duplicate account.');
    }
    
    // Generate username (subemail) from email
    const generatedUsername = email.split('@')[0].toLowerCase();

    // Create User WITHOUT tenant - user will create market manually via setup page
    const user = await this.prismaService.user.create({
      data: {
        email: signupData.email,
        username: generatedUsername,
        password: signupData.password,
        ...(signupData.name && { name: signupData.name }),
        role: 'SHOP_OWNER',
        tenantId: null, // No tenant created automatically - user must create via setup page
        recoveryId,
        emailVerified: true, // Already verified via OTP
      },
    });

    const tenant = null; // No tenant created during signup

    // Mark code as used
    await this.prismaService.passwordReset.update({
      where: { id: resetRecord.id },
      data: { used: true },
    });

    // Clean up pending signup data
    this.pendingSignups.delete(signupDataKey);

    // Log successful registration (no tenant created yet)
    await this.logAuditEvent(
      user.id,
      null, // No tenant yet
      'USER_REGISTERED',
      user.id,
      'user',
      undefined,
      { role: 'SHOP_OWNER' },
      { registrationMethod: 'email', hasRecoveryId: true, setupPending: true }
    );

    // Generate tokens
    const fullUser = await this.prismaService.user.findUnique({
      where: { id: user.id },
      include: { tenant: true },
    });

    if (!fullUser) {
      throw new Error('User not found after creation');
    }

    const tokens = await this.generateTokens(fullUser);

    this.logger.log(`✅ Account created and email verified for: ${email} (no tenant created - user must set up market)`);

    return {
      valid: true,
      message: 'Email verified successfully and account created',
      tokens,
      recoveryId, // Return recovery ID so user can save it
      setupPending: true, // Indicate that user needs to set up market
    };
  }

  async resendVerificationCode(email: string): Promise<{ message: string; previewUrl?: string; code?: string }> {
    // Check for pending signup (not existing user)
    const existingPending = await this.prismaService.passwordReset.findFirst({
      where: {
        email,
        used: false,
        expiresAt: {
          gt: new Date(),
        },
        code: {
          startsWith: 'SIGNUP_',
        },
      },
    });

    if (!existingPending) {
      // Don't reveal if signup exists
      return { message: 'If the email exists, a verification code has been sent' };
    }

    // Check if user already exists (shouldn't happen for pending signup)
    const user = await this.prismaService.user.findUnique({
      where: { email },
    });

    if (user) {
      throw new BadRequestException('Account already exists. Please login instead.');
    }

    // Get signup data from existing pending signup
    // We need to find the code from the existing pending record
    const oldCode = existingPending.code.replace('SIGNUP_', '');
    const signupDataKey = `${email}_${oldCode}`;
    const signupData = this.pendingSignups.get(signupDataKey);

    if (!signupData) {
      throw new BadRequestException('Pending signup not found. Please start signup again.');
    }

    // Check rate limiting
    const signupConfig = this.rateLimitingService.getSignupConfig();
    const rateLimitCheck = await this.rateLimitingService.checkRateLimit(
      email,
      'REGISTRATION',
      signupConfig.maxAttempts,
      signupConfig.windowMs
    );

    if (!rateLimitCheck.allowed) {
      throw new ForbiddenException(`Too many verification code requests. Please try again after ${Math.ceil((rateLimitCheck.resetTime.getTime() - Date.now()) / 60000)} minutes.`);
    }

    // Mark old code as used
    await this.prismaService.passwordReset.update({
      where: { id: existingPending.id },
      data: { used: true },
    });

    // Remove old pending signup
    this.pendingSignups.delete(signupDataKey);

    // Generate new code
    const verificationCode = this.generateResetCode();
    const signupCode = `SIGNUP_${verificationCode}`;
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // Store new verification code
    await this.prismaService.passwordReset.create({
      data: {
        email,
        code: signupCode,
        expiresAt,
      },
    });

    // Store signup data with new code
    this.pendingSignups.set(`${email}_${verificationCode}`, signupData);

    // Send verification email
    const emailResult = await this.emailService.sendVerificationEmail(email, verificationCode);

    const response: any = {
      message: 'Verification code has been sent to your email',
    };

    // In development, return preview URL and code
    if (process.env.NODE_ENV === 'development') {
      response.previewUrl = emailResult.previewUrl;
      response.code = verificationCode;
    }

    return response;
  }

  async login(loginDto: LoginDto, ipAddress?: string, userAgent?: string, fingerprint?: any): Promise<LoginResponseDto> {
    const { email, username, password } = loginDto;
    const safeIpAddress = ipAddress || 'unknown';
    
    // Determine identifier for rate limiting and logging
    const identifier = email || username || 'unknown';

    // Find user by email or username
    let user;
    if (email) {
      user = await this.prismaService.user.findUnique({
        where: { email },
        include: { tenant: true },
      });
    } else if (username) {
      // Try to find by username (subemail)
      user = await this.prismaService.user.findFirst({
        where: { username: username.toLowerCase() },
        include: { tenant: true },
      });
    }

    const isAdmin = user?.role === 'SUPER_ADMIN';

    // Validate email format - check for fake/disposable emails (Skip for Admin, skip if using username)
    if (!isAdmin && email) {
      const emailValidation = await validateEmailWithMx(email);
      if (!emailValidation.isValid) {
        this.logger.warn(`Login attempted with invalid email: ${email} - ${emailValidation.reason}`);
        throw new BadRequestException(emailValidation.reason || 'Invalid email address');
      }
    }

    // Check device fingerprint (Skip for Admin)
    if (fingerprint && !isAdmin) {
        try {
            await this.checkDeviceFingerprint(fingerprint, identifier, safeIpAddress, userAgent);
        } catch (e) {
            this.logger.error('Fingerprint check failed, but allowing login:', e);
        }
    }

    // Check rate limiting for login attempts
    // We still apply rate limiting for admin to prevent brute force on admin account, 
    // but we could increase limits if needed. For now, standard limits apply.
    const loginConfig = this.rateLimitingService.getLoginConfig();
    const rateLimitCheck = await this.rateLimitingService.checkRateLimit(
      identifier, 
      'LOGIN', 
      loginConfig.maxAttempts,
      loginConfig.windowMs
    );

    if (!rateLimitCheck.allowed) {
      await this.logSecurityEvent(
        'BRUTE_FORCE_ATTEMPT',
        'HIGH',
        undefined,
        undefined,
        safeIpAddress,
        userAgent,
        `Rate limited login attempts for: ${identifier}`
      );
      throw new ForbiddenException(`Too many login attempts. Please try again after ${Math.ceil((rateLimitCheck.resetTime.getTime() - Date.now()) / 60000)} minutes.`);
    }

    this.logger.log(`🔧 Login attempt for: ${identifier} from IP: ${safeIpAddress}`);

    if (!user) {
      // User not found (and we already checked rate limit)
      await this.logSecurityEvent(
        'FAILED_LOGIN_ATTEMPT',
        'LOW',
        undefined,
        undefined,
        safeIpAddress,
        userAgent,
        `Failed login attempt for non-existent user: ${identifier}`
      );
      throw new UnauthorizedException('Invalid credentials');
    }



    // Account lock check is handled in AuthController

    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      this.logger.warn(`Login failed: Invalid password for user: ${email}`);
      await this.logSecurityEvent(
        'SUSPICIOUS_LOGIN',
        'MEDIUM',
        user.id,
        user.tenantId,
        safeIpAddress,
        userAgent,
        `Failed login attempt with wrong password for user: ${user.email}`
      );
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if email is verified (skip for admin)
    if (!isAdmin && !user.emailVerified) {
      this.logger.warn(`Login blocked: Email not verified for user: ${email}`);
      throw new UnauthorizedException('Email not verified. Please verify your email before logging in.');
    }

    // Successful login attempt recording is handled in AuthController

    // Log successful login as security event (for tracking location/device)
    await this.logSecurityEvent(
      'SUCCESSFUL_LOGIN',
      'LOW',
      user.id,
      user.tenantId,
      safeIpAddress,
      userAgent,
      `Successful login for user: ${user.email}`,
      { loginMethod: 'email_password' }
    );

    // Fix: Ensure user_tenants record exists if user has tenantId
    // This handles backward compatibility for users created before user_tenants table
    // The backend expects a record in user_tenants to allow login
    if (user.tenantId) {
      try {
        // Use existing linkUserToTenant method to ensure consistency
        await this.linkUserToTenant(user.id, user.tenantId, true);
        this.logger.log(`✅ Ensured user_tenants record exists for user ${user.id} and tenant ${user.tenantId}`);
      } catch (error) {
        // If tenant doesn't exist or other error, log warning but don't fail login
        // This allows users without valid tenants to still log in
        this.logger.warn(`⚠️ Could not link user to tenant during login: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }

    // Log successful login as audit event
    await this.logAuditEvent(
      user.id,
      user.tenantId,
      'USER_LOGIN',
      user.id,
      'user',
      undefined,
      undefined,
      { loginMethod: 'email_password', ipAddress: safeIpAddress }
    );

    // Generate tokens
    const tokens = await this.generateTokens(user);

    this.logger.log(`✅ Login successful for user: ${user.email}`);
    return {
      id: user.id,
      email: user.email,
      username: user.username || undefined,
      role: user.role,
      tenantId: user.tenantId,
      tenantName: user.tenant?.name,
      tenantSubdomain: user.tenant?.subdomain,
      avatar: user.avatar,
      ...tokens,
    };
  }

  /**
   * Login with recovery ID - allows users to recover access using their secret ID
   */
  async loginWithRecoveryId(recoveryId: string, password: string, ipAddress?: string, userAgent?: string): Promise<LoginResponseDto> {
    const safeIpAddress = ipAddress || 'unknown';

    // Normalize recovery ID (remove dashes, uppercase)
    const normalizedRecoveryId = recoveryId.replace(/-/g, '').toUpperCase();

    // Check rate limiting
    const rateLimitCheck = await this.rateLimitingService.checkRateLimit(
      `recovery:${normalizedRecoveryId}`,
      'LOGIN',
      10, // Fewer attempts allowed for recovery
      30 * 60 * 1000 // 30 minutes
    );

    if (!rateLimitCheck.allowed) {
      throw new ForbiddenException('Too many recovery attempts. Please try again later.');
    }

    // Find user by recovery ID
    const user = await this.prismaService.user.findFirst({
      where: {
        recoveryId: {
          equals: normalizedRecoveryId,
        },
      },
    });

    if (!user) {
      await this.logSecurityEvent(
        'SUSPICIOUS_LOGIN',
        'MEDIUM',
        undefined,
        undefined,
        safeIpAddress,
        userAgent,
        `Invalid recovery ID attempt`
      );
      throw new UnauthorizedException('Invalid recovery ID');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      await this.logSecurityEvent(
        'SUSPICIOUS_LOGIN',
        'MEDIUM',
        user.id,
        user.tenantId,
        safeIpAddress,
        userAgent,
        `Failed recovery login: wrong password for user: ${user.email}`
      );
      throw new UnauthorizedException('Invalid credentials');
    }

    // Log successful recovery login
    await this.logAuditEvent(
      user.id,
      user.tenantId,
      'USER_LOGIN',
      user.id,
      'user',
      undefined,
      undefined,
      { loginMethod: 'recovery_id', ipAddress: safeIpAddress }
    );

    // Generate tokens
    const tokens = await this.generateTokens(user);

    this.logger.log(`✅ User logged in via recovery ID: ${user.email}`);

    return {
      id: user.id,
      email: user.email,
      role: user.role,
      tenantId: user.tenantId,
      avatar: user.avatar,
      ...tokens,
    };
  }

  /**
   * Get user email by recovery ID (for "forgot email" feature)
   */
  async getEmailByRecoveryId(recoveryId: string): Promise<{ email: string; maskedEmail: string }> {
    // Try multiple formats
    const normalizedNoDashes = recoveryId.replace(/-/g, '').toUpperCase();
    const withDashes = recoveryId.toUpperCase();
    const original = recoveryId;

    this.logger.log(`Looking for recovery ID: original="${original}", noDashes="${normalizedNoDashes}", withDashes="${withDashes}"`);

    // Try exact match first, then normalized versions
    const user = await this.prismaService.user.findFirst({
      where: {
        OR: [
          { recoveryId: original },
          { recoveryId: withDashes },
          { recoveryId: normalizedNoDashes },
        ],
      },
      select: {
        email: true,
        recoveryId: true,
      },
    });

    if (!user) {
      this.logger.warn(`Recovery ID not found: ${recoveryId}`);
      throw new NotFoundException('Invalid recovery ID');
    }

    this.logger.log(`Found user with recovery ID: ${user.recoveryId}`);

    // Mask email for security (show only first 2 chars and domain)
    const [localPart, domain] = user.email.split('@');
    const maskedLocal = localPart.substring(0, 2) + '***';
    const maskedEmail = `${maskedLocal}@${domain}`;

    return {
      email: user.email,
      maskedEmail,
    };
  }

  /**
   * Recover email by recovery ID - returns masked email for user verification
   * This is a public endpoint - no password required
   */
  async recoverEmailByRecoveryId(recoveryId: string): Promise<{ success: boolean; maskedEmail: string; message: string }> {
    try {
      const result = await this.getEmailByRecoveryId(recoveryId);
      return {
        success: true,
        maskedEmail: result.maskedEmail,
        message: `Your email is: ${result.maskedEmail}`,
      };
    } catch (error) {
      throw new BadRequestException('Invalid recovery ID. Please check and try again.');
    }
  }

  /**
   * Send password reset email using recovery ID
   * This allows users who forgot their email to still reset their password
   */
  async sendPasswordResetByRecoveryId(recoveryId: string): Promise<{ success: boolean; message: string }> {
    try {
      // Get the user's email by recovery ID
      const result = await this.getEmailByRecoveryId(recoveryId);
      
      // Now send the password reset email using the actual email
      await this.forgotPassword({ email: result.email }, 'recovery_id');
      
      return {
        success: true,
        message: 'Password reset email sent successfully',
      };
    } catch (error) {
      // For security, don't reveal if recovery ID was invalid
      throw new BadRequestException('Failed to send reset email. Please check your recovery ID.');
    }
  }

  async refreshTokens(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret',
      });

      // Verify user exists
      const user = await this.prismaService.user.findUnique({
        where: { id: payload.sub },
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Log token refresh
      await this.logAuditEvent(
        user.id,
        user.tenantId,
        'TOKEN_REFRESHED',
        user.id,
        'user'
      );

      return this.generateTokens(user);
    } catch (error) {
      await this.logSecurityEvent(
        'INVALID_REFRESH_TOKEN',
        'MEDIUM',
        undefined,
        undefined,
        undefined,
        undefined,
        `Invalid refresh token attempt: ${error}`
      );
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto, ipAddress?: string): Promise<{ message: string; previewUrl?: string; code?: string }> {
    const { email } = forgotPasswordDto;
    const safeIpAddress = ipAddress || 'unknown';

    // Check rate limiting for password reset
    const passwordResetConfig = this.rateLimitingService.getPasswordResetConfig();
    const rateLimitCheck = await this.rateLimitingService.checkRateLimit(
      email,
      'PASSWORD_RESET',
      passwordResetConfig.maxAttempts,
      passwordResetConfig.windowMs
    );

    if (!rateLimitCheck.allowed) {
      throw new ForbiddenException(`Too many password reset attempts. Please try again after ${Math.ceil((rateLimitCheck.resetTime.getTime() - Date.now()) / 60000)} minutes.`);
    }

    this.logger.log(`🔧 Forgot password request for: ${email} from IP: ${safeIpAddress}`);

    // Check if user exists
    const user = await this.prismaService.user.findUnique({
      where: { email },
    });

    // Don't reveal whether user exists for security
    const response: any = { 
      message: 'If the email exists, a reset code has been sent',
    };

    if (!user) {
      await this.logSecurityEvent(
        'PASSWORD_RESET_ATTEMPT',
        'LOW',
        undefined,
        undefined,
        safeIpAddress,
        undefined,
        `Password reset attempt for non-existent email: ${email}`
      );
      return response;
    }

    // Generate secure reset token
    const resetToken = this.generateResetToken();
    const resetCode = `RESET_${resetToken}`;
    
    // Set expiration (1 hour from now - more time for user to click link)
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

    // Store reset token in database with RESET_ prefix
    try {
      // Delete any existing unused reset tokens for this email
      await this.prismaService.passwordReset.deleteMany({
        where: {
          email,
          used: false,
          code: { startsWith: 'RESET_' },
        },
      });

      await this.prismaService.passwordReset.create({
        data: {
          email,
          code: resetCode,
          expiresAt,
        },
      });

      // Log password reset request
      await this.logAuditEvent(
        user.id,
        user.tenantId,
        'PASSWORD_RESET_REQUESTED',
        user.id,
        'user',
        undefined,
        undefined,
        { ipAddress: safeIpAddress }
      );

      this.logger.log(`✅ Password reset token stored for: ${email}`);
    } catch (error) {
      this.logger.error('❌ Failed to store password reset token:', error);
      throw new Error('Failed to process password reset request');
    }

    // Send password reset link email
    try {
      const emailResult = await this.emailService.sendPasswordResetLinkEmail(email, resetToken);
      
      response.message = 'If the email exists, a password reset link has been sent to your email';
      
      // In development, return preview URL
      if (process.env.NODE_ENV === 'development' && emailResult.previewUrl) {
        response.previewUrl = emailResult.previewUrl;
      }

      return response;
    } catch (emailError) {
      this.logger.error('❌ Email sending failed:', emailError);
      throw new Error('Failed to send password reset email');
    }
  }

  async verifyResetToken(token: string): Promise<{ valid: boolean; message: string; email?: string }> {
    // Verify reset token
    const resetCode = `RESET_${token}`;
    const resetRecord = await this.prismaService.passwordReset.findFirst({
      where: {
        code: resetCode,
        used: false,
        expiresAt: {
          gt: new Date(), // Not expired
        },
      },
    });

    if (!resetRecord) {
      return { valid: false, message: 'Invalid or expired reset link' };
    }

    return { 
      valid: true, 
      message: 'Reset link is valid',
      email: resetRecord.email 
    };
  }

  async verifyResetCode(email: string, code: string): Promise<{ valid: boolean; message: string }> {
    // Check if user exists
    const existingUser = await this.prismaService.user.findUnique({
      where: { email },
    });

    if (!existingUser) {
      // Don't reveal if user exists
      return { valid: false, message: 'Invalid or expired verification code' };
    }

    // Verify OTP code with RESET_ prefix
    const resetCode = `RESET_${code}`;
    const resetRecord = await this.prismaService.passwordReset.findFirst({
      where: {
        email,
        code: resetCode,
        used: false,
        expiresAt: {
          gt: new Date(), // Not expired
        },
      },
    });

    if (!resetRecord) {
      await this.logSecurityEvent(
        'INVALID_RESET_CODE',
        'LOW',
        existingUser.id,
        existingUser.tenantId,
        undefined,
        undefined,
        `Invalid password reset OTP attempt for email: ${email}`
      );
      return { valid: false, message: 'Invalid or expired verification code' };
    }

    return { valid: true, message: 'Verification code is valid' };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto, ipAddress?: string): Promise<{ message: string }> {
    const { email, code, token, newPassword } = resetPasswordDto as any;
    const safeIpAddress = ipAddress || 'unknown';

    let resetRecord;
    let userEmail: string;

    // Support both token-based (new) and code-based (legacy) reset
    if (token) {
      // Token-based reset (new method)
      const resetCode = `RESET_${token}`;
      resetRecord = await this.prismaService.passwordReset.findFirst({
        where: {
          code: resetCode,
          used: false,
          expiresAt: {
            gt: new Date(),
          },
        },
      });

      if (!resetRecord) {
        throw new BadRequestException('Invalid or expired reset link');
      }

      userEmail = resetRecord.email;
    } else if (email && code) {
      // Code-based reset (legacy method)
      const existingUser = await this.prismaService.user.findUnique({
        where: { email },
      });

      if (!existingUser) {
        throw new BadRequestException('Invalid or expired verification code');
      }

      const resetCode = `RESET_${code}`;
      resetRecord = await this.prismaService.passwordReset.findFirst({
        where: {
          email,
          code: resetCode,
          used: false,
          expiresAt: {
            gt: new Date(),
          },
        },
      });

      if (!resetRecord) {
        await this.logSecurityEvent(
          'INVALID_RESET_CODE',
          'MEDIUM',
          existingUser.id,
          existingUser.tenantId,
          safeIpAddress,
          undefined,
          `Invalid password reset attempt for email: ${email}`
        );
        throw new BadRequestException('Invalid or expired verification code');
      }

      userEmail = email;
    } else {
      throw new BadRequestException('Token or email and code are required');
    }

    // Get user
    const existingUser = await this.prismaService.user.findUnique({
      where: { email: userEmail },
    });

    if (!existingUser) {
      throw new BadRequestException('Invalid or expired reset link');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update user password and mark reset code as used in a transaction
    await this.prismaService.$transaction(async (tx: { user: { update: (arg0: { where: { email: string; }; data: { password: string; }; }) => any; }; passwordReset: { update: (arg0: { where: { id: any; }; data: { used: boolean; }; }) => any; deleteMany: (arg0: { where: { email: string; used: boolean; }; }) => any; }; }) => {
        // Update user password
        await tx.user.update({
          where: { email: userEmail },
          data: { password: hashedPassword },
        });

        // Mark reset code as used
        await tx.passwordReset.update({
          where: { id: resetRecord.id },
          data: { used: true },
        });

        // Delete all other reset codes for this email
        await tx.passwordReset.deleteMany({
          where: {
            email: userEmail,
            used: false,
          },
        });
      });

      // Log password reset
      await this.logAuditEvent(
        existingUser.id,
        existingUser.tenantId,
        'PASSWORD_RESET',
        existingUser.id,
        'user',
        undefined,
        undefined,
        { ipAddress: safeIpAddress }
      );

      // Invalidate all refresh tokens for security
      await this.prismaService.refreshToken.deleteMany({
        where: { userId: existingUser.id },
      });

    this.logger.log(`✅ Password reset successfully for user: ${userEmail}`);

    return { message: 'Password reset successfully' };
  }

  async createStaffUser(tenantId: string, creatingUserId: string, staffData: { email: string; password: string; permissions: string[] }) {
    // Verify creating user has permission to create staff
    const creatingUser = await this.prismaService.user.findFirst({
      where: { 
        id: creatingUserId,
        tenantId,
        role: { in: ['SUPER_ADMIN', 'SHOP_OWNER'] }
      },
    });

    if (!creatingUser) {
      throw new ForbiddenException('Insufficient permissions to create staff users');
    }

    // Check if user already exists
    const existingUser = await this.prismaService.user.findUnique({
      where: { email: staffData.email },
    });

    if (existingUser) {
      throw new ConflictException('User already exists');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(staffData.password, 12);

    // Create staff user and permissions in transaction
    const result = await this.prismaService.$transaction(async (tx: { user: { create: (arg0: { data: { email: string; password: string; role: string; tenantId: string; }; }) => any; }; staffPermission: { create: (arg0: { data: { userId: any; tenantId: string; permission: string; grantedBy: string; }; }) => any; }; }) => {
      // Create user as staff
      const user = await tx.user.create({
        data: {
          email: staffData.email,
          password: hashedPassword,
          role: 'STAFF',
          tenantId,
        },
      });

      // Create staff permissions
      const permissions = await Promise.all(
        staffData.permissions.map(permission =>
          tx.staffPermission.create({
            data: {
              userId: user.id,
              tenantId,
              permission,
              grantedBy: creatingUserId,
            },
          })
        )
      );

      return { user, permissions };
    });

    // Log staff creation
    await this.logAuditEvent(
      creatingUserId,
      tenantId,
      'STAFF_CREATED',
      result.user.id,
      'user',
      undefined,
      { permissions: staffData.permissions },
      { staffEmail: staffData.email }
    );

    this.logger.log(`✅ Staff user created: ${staffData.email} by user: ${creatingUserId}`);

    return result;
  }

  async getUserPermissions(userId: string, tenantId: string): Promise<string[]> {
    const permissions = await this.prismaService.staffPermission.findMany({
      where: {
        userId,
        tenantId,
      },
      select: { permission: true },
    });

    return permissions.map((p: { permission: any; }) => p.permission);
  }

  async checkPermission(userId: string, tenantId: string, permission: string): Promise<boolean> {
    const user = await this.prismaService.user.findFirst({
      where: { id: userId, tenantId },
    });

    if (!user) {
      return false;
    }

    // Super admins and shop owners have all permissions
    if (user.role === 'SUPER_ADMIN' || user.role === 'SHOP_OWNER') {
      return true;
    }

    // Check specific permission for staff
    const hasPermission = await this.prismaService.staffPermission.findFirst({
      where: {
        userId,
        tenantId,
        permission,
      },
    });

    return !!hasPermission;
  }

  async getStaffUsers(tenantId: string) {
    return this.prismaService.user.findMany({
      where: {
        tenantId,
        role: 'STAFF',
      },
      include: {
        staffPermissions: {
          select: {
            permission: true,
            grantedAt: true,
            grantedBy: true,
          },
        },
      },
      select: {
        id: true,
        email: true,
        createdAt: true,
        staffPermissions: true,
      },
    });
  }

  async updateStaffPermissions(tenantId: string, updatingUserId: string, staffUserId: string, permissions: string[]) {
    // Verify updating user has permission
    const updatingUser = await this.prismaService.user.findFirst({
      where: { 
        id: updatingUserId,
        tenantId,
        role: { in: ['SUPER_ADMIN', 'SHOP_OWNER'] }
      },
    });

    if (!updatingUser) {
      throw new ForbiddenException('Insufficient permissions to update staff permissions');
    }

    // Verify staff user exists and belongs to tenant
    const staffUser = await this.prismaService.user.findFirst({
      where: { 
        id: staffUserId,
        tenantId,
        role: 'STAFF'
      },
    });

    if (!staffUser) {
      throw new NotFoundException('Staff user not found');
    }

    // Update permissions in transaction
    const result = await this.prismaService.$transaction(async (tx: { staffPermission: { deleteMany: (arg0: { where: { userId: string; tenantId: string; }; }) => any; create: (arg0: { data: { userId: string; tenantId: string; permission: string; grantedBy: string; }; }) => any; }; }) => {
      // Remove existing permissions
      await tx.staffPermission.deleteMany({
        where: {
          userId: staffUserId,
          tenantId,
        },
      });

      // Create new permissions
      const newPermissions = await Promise.all(
        permissions.map(permission =>
          tx.staffPermission.create({
            data: {
              userId: staffUserId,
              tenantId,
              permission,
              grantedBy: updatingUserId,
            },
          })
        )
      );

      return newPermissions;
    });

    // Log permission update
    await this.logAuditEvent(
      updatingUserId,
      tenantId,
      'STAFF_PERMISSIONS_UPDATED',
      staffUserId,
      'user',
      undefined,
      { permissions },
      { staffEmail: staffUser.email }
    );

    this.logger.log(`✅ Staff permissions updated for user: ${staffUser.email} by user: ${updatingUserId}`);

    return result;
  }

  private async generateTokens(user: any) {
    // Ensure we have the latest tenantId from the database
    // This handles cases where tenantId was updated after user object was loaded
    let tenantId = user.tenantId;
    
    // If tenantId is missing, try to get it from user_tenants table
    if (!tenantId) {
      try {
        const userTenant = await this.prismaService.userTenant.findFirst({
          where: { userId: user.id, isOwner: true },
          orderBy: { createdAt: 'desc' }
        });
        if (userTenant) {
          tenantId = userTenant.tenantId;
          this.logger.log(`Retrieved tenantId ${tenantId} from user_tenants for user ${user.id}`);
        }
      } catch (error) {
        this.logger.warn(`Could not retrieve tenantId from user_tenants for user ${user.id}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
    
    const payload = { 
      sub: user.id, 
      email: user.email, 
      role: user.role, 
      tenantId: tenantId || null
    };

    // Log token generation for debugging
    if (!tenantId && user.role !== 'SUPER_ADMIN') {
      this.logger.warn(`Generating JWT token without tenantId for user ${user.id} (${user.email}). User may need to set up a market.`);
    } else {
      this.logger.debug(`Generating JWT token for user ${user.id} with tenantId: ${tenantId}`);
    }

    const accessToken = this.jwtService.sign(payload);
    
    // Generate unique refresh token
    const refreshTokenPayload = {
      ...payload,
      jti: crypto.randomBytes(16).toString('hex'), // Unique ID
      type: 'refresh'
    };
    
    const refreshToken = this.jwtService.sign(refreshTokenPayload, {
      secret: process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret',
      expiresIn: '7d',
    });

    // Store refresh token in database
    await this.storeRefreshToken(user.id, refreshToken);

    return { accessToken, refreshToken };
  }

  private async storeRefreshToken(userId: string, token: string) {
    try {
      // Use upsert to handle potential collisions or existing tokens
      // The token itself is the unique key
      await this.prismaService.refreshToken.upsert({
        where: { token },
        create: {
          token,
          userId,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        },
        update: {
          // If it exists, just update the expiration
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        },
      });
    } catch (error) {
      this.logger.error('Failed to store refresh token:', error);
      // Don't throw, just log. Login should still succeed with access token.
    }
  }

  private generateResetCode(): string {
    // Generate 6-digit numeric code
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  private generateResetToken(): string {
    // Generate secure random token for password reset link
    return crypto.randomBytes(32).toString('hex');
  }

  private async checkDeviceFingerprint(fingerprint: any, identifier: string, ip: string, userAgent?: string) {
    this.logger.log(`🔍 Checking device fingerprint for ${identifier}. Fingerprint data present: ${!!fingerprint}, IP: ${ip}`);
    
    // Server-side IP reputation check (more reliable than client-side)
    const ipCheck = await checkIpReputation(ip);
    const isVpnFromIp = ipCheck.isVpn || ipCheck.isProxy || ipCheck.isTor;
    
    if (isVpnFromIp) {
      this.logger.warn(`🔴 VPN/Proxy detected via IP check for ${identifier}: IP=${ip}, ISP=${ipCheck.isp}, Country=${ipCheck.country}`);
    }
    
    // Use fingerprint data if available, but prefer IP check for VPN
    const { visitorId, isVM, isVpn: isVpnFromClient, os, components, riskScore } = fingerprint || {};
    const isVpn = isVpnFromIp || isVpnFromClient; // Either detection method
    
    let relatedEmails: string[] = [];
    let userId: string | undefined;
    let tenantId: string | undefined;
    let email = identifier.includes('@') ? identifier : undefined;

    // Find user to associate event and check tenant settings
    try {
        // Try to find user by email or username
        let user = null;
        if (email) {
            user = await this.prismaService.user.findUnique({
                where: { email },
                select: { 
                    id: true, 
                    email: true,
                    tenantId: true,
                    role: true,
                    username: true,
                    tenant: {
                        select: { id: true, subdomain: true }
                    }
                }
            });
        } else {
            user = await this.prismaService.user.findFirst({
                where: { username: identifier.toLowerCase() },
                select: { 
                    id: true, 
                    email: true,
                    tenantId: true,
                    role: true,
                    username: true,
                    tenant: {
                        select: { id: true, subdomain: true }
                    }
                }
            });
            if (user) {
                email = user.email;
            }
        }

        if (user) {
            userId = user.id;
            tenantId = user.tenantId || undefined;

            // SUPER_ADMIN bypass VPN check
            if (user.role === 'SUPER_ADMIN') {
              this.logger.log(`Bypassing VPN check for SUPER_ADMIN: ${email}`);
            } else if (isVpn) {
              // Automatic VPN blocking - Enforce security without user setting
              this.logger.warn(`Blocking login for ${email} due to VPN detection.`);
              throw new ForbiddenException('Access denied: VPN/Proxy usage is not allowed. Please disable your VPN and try again.');
            }
        } else if (isVpn) {
          // No user found but VPN detected - still block for new signups
          this.logger.warn(`Blocking signup/login attempt for ${identifier} due to VPN detection (no user found).`);
          throw new ForbiddenException('Access denied: VPN/Proxy usage is not allowed. Please disable your VPN and try again.');
        }
    } catch (e) {
        if (e instanceof ForbiddenException) throw e;
        this.logger.warn(`Could not find user for fingerprint logging: ${identifier}`);
    }

    // Check device history for other accounts
    try {
        // Fetch recent DEVICE_FINGERPRINT events and filter in code (MySQL doesn't support JSON path queries like PostgreSQL)
        const recentEvents = await this.prismaService.securityEvent.findMany({
            where: {
                type: 'DEVICE_FINGERPRINT',
            },
            select: {
                metadata: true
            },
            take: 500,
            orderBy: { createdAt: 'desc' }
        });

        const emailSet = new Set<string>();
        if (email) emailSet.add(email);

        for (const event of recentEvents) {
            try {
                const meta: any = typeof event.metadata === 'string' ? JSON.parse(event.metadata) : event.metadata;
                // Filter by visitorId in code
                if (meta && meta.fingerprint && meta.fingerprint.visitorId === visitorId && meta.email) {
                    emailSet.add(meta.email);
                }
            } catch {
                // Skip invalid JSON
            }
        }
        relatedEmails = Array.from(emailSet);

    } catch (e) {
        this.logger.error('Error checking device history', e);
    }

    // Log the fingerprint event with related emails
    await this.logSecurityEvent(
      'DEVICE_FINGERPRINT',
      'LOW',
      userId,
      tenantId,
      ip,
      userAgent,
      `Device fingerprint collected for ${email || identifier}`,
      { fingerprint, email: email || identifier, relatedEmails, isVpn, os }
    );

    // 1. VM Detection
    if (isVM) {
      await this.logSecurityEvent(
        'VM_DETECTED',
        'MEDIUM',
        userId,
        tenantId,
        ip,
        userAgent,
        `Virtual Machine detected during auth for ${email || identifier}`,
        { fingerprint, email: email || identifier }
      );
    }

    // 2. High Risk Score
    if (riskScore > 70) {
       await this.logSecurityEvent(
        'HIGH_RISK_DEVICE',
        'HIGH',
        userId,
        tenantId,
        ip,
        userAgent,
        `High risk device detected (Score: ${riskScore}) for ${email || identifier}`,
        { fingerprint, email: email || identifier }
      );
    }

    // 3. Multiple Accounts Check
    if (relatedEmails.length > 3) {
            await this.logSecurityEvent(
            'MULTIPLE_ACCOUNTS_ON_DEVICE',
            'CRITICAL',
            userId,
            tenantId,
            ip,
            userAgent,
            `Device used by ${relatedEmails.length} different emails: ${relatedEmails.join(', ')}`,
            { fingerprint, emails: relatedEmails }
        );
    }
  }



 // In auth.service.ts - fix the logAuditEvent method
private async logAuditEvent(
  userId: string,
  tenantId: string,
  action: string,
  resourceId?: string,
  resourceType?: string,
  oldValues?: any,
  newValues?: any,
  metadata?: any,
  ipAddress?: string,
  userAgent?: string,
): Promise<void> {
  try {
    await this.prismaService.auditLog.create({
      data: {
        userId,
        tenantId,
        action,
        resourceId,
        resourceType,
        oldValues: oldValues ? JSON.stringify(oldValues) : null, // Convert to JSON string
        newValues: newValues ? JSON.stringify(newValues) : null, // Convert to JSON string
        metadata: metadata ? JSON.stringify(metadata) : null,    // Convert to JSON string
        ipAddress,
        userAgent,
      },
    });
  } catch (error) {
    this.logger.error('Failed to log audit event:', error);
  }
}

  private async logSecurityEvent(
    type: string,
    severity: string,
    userId?: string,
    tenantId?: string,
    ipAddress?: string,
    userAgent?: string,
    description?: string,
    metadata?: any,
  ): Promise<void> {
    try {
      // Get geolocation data
      let geoData: any = {};
      if (ipAddress && ipAddress !== 'unknown') {
        try {
          const { checkIpReputation } = await import('../../utils/ip-checker');
          const ipInfo = await checkIpReputation(ipAddress);
          geoData = {
            country: ipInfo.country,
            countryCode: ipInfo.countryCode,
            city: ipInfo.city,
            region: ipInfo.region,
            latitude: ipInfo.latitude,
            longitude: ipInfo.longitude,
            isp: ipInfo.isp,
            isVpn: ipInfo.isVpn,
            isProxy: ipInfo.isProxy,
          };
        } catch (geoError) {
          this.logger.warn('Failed to get geolocation for IP:', geoError);
        }
      }

      // Parse user agent to get OS, browser, device
      let deviceInfo = { os: 'Unknown', browser: 'Unknown', device: 'Unknown' };
      if (userAgent) {
        try {
          const { parseUserAgent } = await import('../../utils/user-agent-parser');
          deviceInfo = parseUserAgent(userAgent);
        } catch (parseError) {
          this.logger.warn('Failed to parse user agent:', parseError);
        }
      }

      await this.prismaService.securityEvent.create({
        data: {
          type,
          severity,
          userId: userId || undefined,
          tenantId: tenantId || undefined,
          ipAddress: ipAddress || undefined,
          userAgent: userAgent || undefined,
          description: description || `Security event: ${type}`,
          metadata: metadata ? JSON.stringify(metadata) : undefined,
          // Geolocation fields
          country: geoData.country,
          countryCode: geoData.countryCode,
          city: geoData.city,
          region: geoData.region,
          latitude: geoData.latitude,
          longitude: geoData.longitude,
          isp: geoData.isp,
          isVpn: geoData.isVpn || false,
          isProxy: geoData.isProxy || false,
          // Device info fields
          os: deviceInfo.os,
          browser: deviceInfo.browser,
          device: deviceInfo.device,
        },
      });

      this.logger.log(`📋 Security event logged: ${type} (severity: ${severity}) - IP: ${ipAddress} - OS: ${deviceInfo.os} - Location: ${geoData.city || 'Unknown'}, ${geoData.country || 'Unknown'}`);
    } catch (error) {
      this.logger.error('Failed to log security event:', error);
      if (error instanceof Error) {
        this.logger.error(error.stack);
      }
    }
  }

  // Removed duplicate createTestSecurityEvent - using the one at line 39

  async validateUser(payload: any) {
    return await this.prismaService.user.findUnique({
      where: { id: payload.sub },
      include: { tenant: true },
    });
  }

  async getAuditLogs(filters?: { tenantId?: string; page?: number; limit?: number }) {
    const page = filters?.page || 1;
    const limit = filters?.limit || 50;
    const skip = (page - 1) * limit;

    const where: any = {};
    if (filters?.tenantId) where.tenantId = filters.tenantId;

    const [logs, total] = await Promise.all([
      this.prismaService.auditLog.findMany({
        where,
        include: {
          user: {
            select: { email: true, name: true },
          },
          tenant: {
            select: { name: true, subdomain: true },
          },
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      this.prismaService.auditLog.count({ where }),
    ]);

    // Format logs to match frontend expectations
    const formattedLogs = logs.map(log => ({
      id: log.id,
      action: log.action,
      resourceType: log.resourceType,
      resourceId: log.resourceId,
      details: `${log.action} on ${log.resourceType || 'system'}`,
      createdAt: log.createdAt,
      user: { email: log.user?.email || 'System', name: log.user?.name },
      tenant: log.tenant,
      oldValues: log.oldValues,
      newValues: log.newValues,
      metadata: log.metadata,
    }));

    return {
      logs: formattedLogs,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async logErrorEvent(params: {
    message: string;
    stack?: string;
    userId?: string;
    tenantId?: string;
    context?: string;
    severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    metadata?: Record<string, any>;
  }) {
    const { message, stack, userId, tenantId, context, severity = 'HIGH', metadata = {} } = params;
    try {
      await this.prismaService.auditLog.create({
        data: {
          userId: userId || undefined,
          tenantId: tenantId || undefined,
          action: 'ERROR',
          resourceType: context || 'SYSTEM',
          resourceId: severity,
          oldValues: null,
          newValues: null,
          ipAddress: metadata?.ipAddress,
          userAgent: metadata?.userAgent,
          metadata: JSON.stringify({
            severity,
            message,
            stack,
            ...metadata,
          }),
        },
      });
    } catch (error) {
      this.logger.error('Failed to log error event:', error);
    }
  }

  async getErrorLogs(filters?: { tenantId?: string; page?: number; limit?: number }) {
    const page = filters?.page || 1;
    const limit = filters?.limit || 50;
    const skip = (page - 1) * limit;

    const where: any = {
      action: 'ERROR',
    };
    if (filters?.tenantId) where.tenantId = filters.tenantId;

    const [logs, total] = await Promise.all([
      this.prismaService.auditLog.findMany({
        where,
        include: {
          user: { select: { email: true, name: true } },
          tenant: { select: { name: true, subdomain: true } },
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      this.prismaService.auditLog.count({ where }),
    ]);

    const formattedLogs = logs.map((log) => {
      let meta: any = log.metadata;
      if (typeof meta === 'string') {
        try { meta = JSON.parse(meta); } catch (e) { meta = {}; }
      }
      return {
        id: log.id,
        action: 'ERROR',
        resourceType: log.resourceType,
        resourceId: log.resourceId,
        severity: meta?.severity || 'HIGH',
        details: meta?.message || log.metadata || 'System error',
        createdAt: log.createdAt,
        user: { email: log.user?.email || 'System', name: log.user?.name },
        tenant: log.tenant,
        metadata: meta,
      };
    });

    return {
      logs: formattedLogs,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async getSecurityEvents(filters?: { tenantId?: string; page?: number; limit?: number }) {
    const page = filters?.page || 1;
    const limit = filters?.limit || 50;
    const skip = (page - 1) * limit;

    const where: any = {};
    if (filters?.tenantId) where.tenantId = filters.tenantId;

    const [events, total] = await Promise.all([
      this.prismaService.securityEvent.findMany({
        where,
        include: {
          user: {
            select: { email: true },
          },
          tenant: {
            select: { name: true, subdomain: true },
          },
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      this.prismaService.securityEvent.count({ where }),
    ]);

    // Format events to match frontend expectations
    const formattedLogs = events.map(log => {
      let metadata: any = log.metadata;
      if (typeof metadata === 'string') {
        try { metadata = JSON.parse(metadata); } catch (e) { metadata = {}; }
      }
      return {
        id: log.id,
        action: log.type,
        details: log.description,
        ipAddress: log.ipAddress || '-',
        severity: log.severity,
        createdAt: log.createdAt,
        user: { email: log.user?.email || 'System' },
        tenant: log.tenant,
        metadata: {
          ...metadata,
          country: log.country,
          city: log.city,
          isVpn: log.isVpn,
          isp: log.isp,
          os: log.os,
          browser: log.browser,
          device: log.device,
        },
      };
    });

    return {
      logs: formattedLogs,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

// Add to your existing AuthService in auth.service.ts

async validateOrCreateUserFromOAuth(oauthUser: {
  email: string;
  firstName: string;
  lastName: string;
  picture?: string;
}) {
  this.logger.log('🔧 Processing OAuth user:', oauthUser.email);

  // Check if user exists
  let user = await this.prismaService.user.findFirst({
    where: { email: oauthUser.email },
    include: { tenant: true },
  });

  if (user) {
    this.logger.log('✅ Existing user found, generating tokens');
    
    const tokens = await this.generateTokens(user);
    
    await this.logAuditEvent(
      user.id,
      user.tenantId,
      'USER_LOGIN_OAUTH',
      user.id,
      'user',
      undefined,
      undefined,
      { loginMethod: 'google_oauth' }
    );

    return {
      id: user.id,
      email: user.email,
      role: user.role,
      tenantId: user.tenantId,
      ...tokens,
    };
  }

  this.logger.log('🆕 Creating new user from OAuth');

  const tempSubdomain = `temp-${Date.now()}`;
  
  const result = await this.prismaService.$transaction(async (tx: { tenant: { create: (arg0: { data: { name: string; subdomain: string; plan: string; status: string; }; }) => any; }; user: { create: (arg0: { data: { email: string; password: string; role: string; tenantId: any; oauthProvider: string; emailVerified: boolean; avatar: string | undefined; setupCompleted: boolean; }; }) => any; }; }) => {
    // ✅ FIX: Use 'ACTIVE' status which exists in your enum
    const tenant = await tx.tenant.create({
      data: {
        name: `${oauthUser.firstName} ${oauthUser.lastName}'s Store`,
        subdomain: tempSubdomain,
        plan: 'STARTER',
        status: 'ACTIVE', // This is valid in your Status enum
      },
    });

    const user = await tx.user.create({
      data: {
        email: oauthUser.email,
        password: '',
        role: 'SHOP_OWNER',
        tenantId: tenant.id,
        oauthProvider: 'GOOGLE',
        emailVerified: true,
        avatar: oauthUser.picture,
        setupCompleted: false,
      },
    });

    return { user, tenant };
  });

  const tokens = await this.generateTokens(result.user);

  await this.logAuditEvent(
    result.user.id,
    result.tenant.id,
    'USER_REGISTERED_OAUTH',
    result.user.id,
    'user',
    undefined,
    { 
      role: 'SHOP_OWNER', 
      subdomain: tempSubdomain,
      oauthProvider: 'GOOGLE'
    },
    { registrationMethod: 'google_oauth', setupPending: true }
  );

  this.logger.log('✅ New OAuth user created:', result.user.email);

  return {
    id: result.user.id,
    email: result.user.email,
    role: result.user.role,
    tenantId: result.tenant.id,
    setupPending: true, // We'll still track this in the response
    ...tokens,
  };
}

async completeOAuthSetup(
  userId: string,
  setupData: {
    storeName: string;
    subdomain: string;
  }
) {
  this.logger.log('Completing OAuth setup for user: ' + userId);
  
  const user = await this.prismaService.user.findUnique({
    where: { id: userId },
    include: { tenant: true },
  });

  if (!user) {
    throw new NotFoundException('User not found');
  }

  // Check if subdomain is available
  const existingTenant = await this.prismaService.tenant.findUnique({
    where: { subdomain: setupData.subdomain },
  });

  if (existingTenant && existingTenant.id !== user.tenantId) {
    throw new ConflictException('Subdomain already taken');
  }

  // Update tenant with real business info
  const updatedTenant = await this.prismaService.tenant.update({
    where: { id: user.tenantId },
    data: {
      name: setupData.storeName,
      subdomain: setupData.subdomain,
      status: 'ACTIVE',
    },
  });

  // Log setup completion
  await this.logAuditEvent(
    userId,
    user.tenantId,
    'OAUTH_SETUP_COMPLETED',
    userId,
    'user',
    undefined,
    { storeName: setupData.storeName, subdomain: setupData.subdomain }
  );

  this.logger.log('OAuth setup completed for user: ' + userId);

  return {
    message: 'Setup completed successfully',
    tenant: updatedTenant,
  };
}


  // Helper method to safely handle IP addresses
  private getSafeIpAddress(ipAddress: string | undefined): string {
    return ipAddress || 'unknown';
  }

  // ==================== MARKET MANAGEMENT ====================

  /**
   * Get all markets (tenants) for a user
   */
  async getUserMarkets(userId: string) {
    try {
      if (!userId) {
        throw new UnauthorizedException('User ID is required');
      }

      const userTenants = await this.prismaService.userTenant.findMany({
        where: { userId },
        include: {
          tenant: {
            select: {
              id: true,
              name: true,
              subdomain: true,
              plan: true,
              status: true,
              createdAt: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
      });

      return userTenants.map((ut) => ({
        id: ut.tenant.id,
        name: ut.tenant.name,
        subdomain: ut.tenant.subdomain,
        plan: ut.tenant.plan,
        status: ut.tenant.status,
        createdAt: ut.tenant.createdAt,
        isOwner: ut.isOwner,
        isActive: ut.tenant.id === userTenants.find((u) => u.userId === userId && u.tenantId === ut.tenant.id)?.tenantId,
      }));
    } catch (error) {
      this.logger.error('Error in getUserMarkets:', error);
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new InternalServerErrorException('Failed to fetch user markets');
    }
  }

  /**
   * Check if user can create a new market (check limit)
   */
  async canCreateMarket(userId: string): Promise<{ allowed: boolean; currentCount: number; limit: number }> {
    try {
      if (!userId) {
        throw new UnauthorizedException('User ID is required');
      }

      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
        select: { marketLimit: true },
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Ensure marketLimit is at least 2 (default)
      const marketLimit = user.marketLimit || 2;

      const currentCount = await this.prismaService.userTenant.count({
        where: { userId, isOwner: true },
      });

      // User can create a market if currentCount is strictly less than the limit
      // This ensures if limit is 1, user can create 1 market (when currentCount is 0)
      const allowed = currentCount < marketLimit;

      return {
        allowed,
        currentCount,
        limit: marketLimit,
      };
    } catch (error) {
      this.logger.error('Error in canCreateMarket:', error);
      if (error instanceof UnauthorizedException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerErrorException('Failed to check market creation limit');
    }
  }

  /**
   * Create UserTenant relationship (link user to tenant)
   */
  async linkUserToTenant(userId: string, tenantId: string, isOwner: boolean = true) {
    // Check if relationship already exists
    const existing = await this.prismaService.userTenant.findUnique({
      where: {
        userId_tenantId: {
          userId,
          tenantId,
        },
      },
    });

    if (existing) {
      return existing;
    }

    return this.prismaService.userTenant.create({
      data: {
        userId,
        tenantId,
        isOwner,
      },
    });
  }

  /**
   * Switch user's active tenant
   */
  async switchActiveTenant(userId: string, tenantId: string) {
    // Verify user has access to this tenant
    const userTenant = await this.prismaService.userTenant.findUnique({
      where: {
        userId_tenantId: {
          userId,
          tenantId,
        },
      },
    });

    if (!userTenant) {
      throw new ForbiddenException('User does not have access to this tenant');
    }

    // Update user's active tenant
    await this.prismaService.user.update({
      where: { id: userId },
      data: { tenantId },
    });

    return { success: true, tenantId };
  }

  /**
   * Update user's market limit (admin only)
   */
  async updateMarketLimit(userId: string, limit: number) {
    if (limit < 1) {
      throw new BadRequestException('Market limit must be at least 1');
    }

    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.prismaService.user.update({
      where: { id: userId },
      data: { marketLimit: limit },
    });
  }

  /**
   * Get user's market limit
   */
  async getUserMarketLimit(userId: string) {
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
      select: { marketLimit: true },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const currentCount = await this.prismaService.userTenant.count({
      where: { userId, isOwner: true },
    });

    return {
      limit: user.marketLimit,
      currentCount,
      remaining: Math.max(0, user.marketLimit - currentCount),
    };
  }

  /**
   * Create tenant in auth database and link to user
   */
  async createTenantAndLink(userId: string, tenantData: { id: string; name: string; subdomain: string; plan?: string; status?: string }) {
    // Check market limit
    const limitCheck = await this.canCreateMarket(userId);
    if (!limitCheck.allowed) {
      throw new ForbiddenException(
        `Market limit reached. You have ${limitCheck.currentCount} of ${limitCheck.limit} markets.`
      );
    }

    // Create tenant in auth database
    const tenant = await this.prismaService.tenant.create({
      data: {
        id: tenantData.id,
        name: tenantData.name,
        subdomain: tenantData.subdomain,
        plan: (tenantData.plan as any) || 'STARTER',
        status: (tenantData.status as any) || 'ACTIVE',
      },
    });

    // Link user to tenant
    await this.linkUserToTenant(userId, tenant.id, true);

    // Update user's active tenant if they don't have one
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
      select: { tenantId: true },
    });

    if (!user?.tenantId) {
      await this.prismaService.user.update({
        where: { id: userId },
        data: { tenantId: tenant.id },
      });
    }

    return tenant;
  }
}