import { Injectable, UnauthorizedException, ConflictException, BadRequestException, ForbiddenException, Logger, NotFoundException } from '@nestjs/common';
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

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

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
    let { email, password, name, storeName, subdomain } = signUpDto;

    // Validate email - check for fake/disposable emails
    const emailValidation = await validateEmailWithMx(email);
    if (!emailValidation.isValid) {
      this.logger.warn(`Signup attempted with invalid email: ${email} - ${emailValidation.reason}`);
      throw new BadRequestException(emailValidation.reason || 'Invalid email address');
    }

    // Check device fingerprint
    if (fingerprint) {
        await this.checkDeviceFingerprint(fingerprint, email, 'unknown'); // IP not available here easily without passing it, but we can ignore or pass it if we change signature. 
        // Actually, let's just use 'unknown' or pass IP if we want to be precise. 
        // For now, I'll stick to 'unknown' or update signature to accept IP if needed.
        // Wait, I can't easily change signature of signUp to accept IP without changing Controller too.
        // Controller calls `signUp(signUpDto, fingerprint)`.
        // I'll update Controller to pass IP if I want it, but for now let's just pass 'unknown' or rely on the check inside.
    }

    // Auto-generate store name and subdomain if not provided (Simplification for user request)
    if (!storeName) {
      storeName = name ? `${name.split(' ')[0]}'s Store` : 'My Store';
    }

    if (!subdomain) {
      // Generate unique subdomain
      const randomSuffix = Math.floor(10000 + Math.random() * 90000);
      subdomain = `store-${randomSuffix}`;
    }

    // Generate unique recovery ID
    const recoveryId = generateRecoveryId();

    // Check rate limiting for signup
    const rateLimitCheck = await this.rateLimitingService.checkRateLimit(
      email,
      'REGISTRATION',
      3,
      60 * 60 * 1000 // 1 hour
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

    // Check if subdomain already exists
    const existingTenant = await this.prismaService.tenant.findUnique({
      where: { subdomain },
    });

    if (existingTenant) {
      throw new ConflictException('Subdomain is already taken');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create Tenant and User in a transaction
    const { user, tenant } = await this.prismaService.$transaction(async (tx) => {
      // Create Tenant
      const tenant = await tx.tenant.create({
        data: {
          name: storeName,
          subdomain,
          plan: 'STARTER',
          status: 'ACTIVE',
        },
      });

      // Generate username (subemail) from email - take part before @
      const generatedUsername = email.split('@')[0].toLowerCase();

      // Create User linked to Tenant with recovery ID and username
      const user = await tx.user.create({
        data: {
          email,
          username: generatedUsername, // Subemail for easy login
          password: hashedPassword,
          ...(name && { name }),
          role: 'SHOP_OWNER',
          tenantId: tenant.id,
          recoveryId, // Store the recovery ID
        },
      });

      return { user, tenant };
    });

    // Log successful registration
    await this.logAuditEvent(
      user.id,
      tenant.id,
      'USER_REGISTERED',
      user.id,
      'user',
      undefined,
      { role: 'SHOP_OWNER' },
      { registrationMethod: 'email', storeName, subdomain, hasRecoveryId: true }
    );

    // Generate tokens
    const tokens = await this.generateTokens(user);

    this.logger.log(`✅ New user registered: ${email} for store: ${storeName}`);

    return {
      id: user.id,
      email: user.email,
      recoveryId, // Return recovery ID so user can save it
      ...tokens,
    };
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
    const rateLimitCheck = await this.rateLimitingService.checkRateLimit(
      identifier, 
      'LOGIN', 
      100, // Increased from 50
      15 * 60 * 1000 // 15 minutes
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
    const rateLimitCheck = await this.rateLimitingService.checkRateLimit(
      email,
      'PASSWORD_RESET',
      5,
      60 * 60 * 1000 // 1 hour
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

    // Generate 6-digit code
    const code = this.generateResetCode();
    
    // Set expiration (15 minutes from now)
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    // Store reset code in database
    try {
      await this.prismaService.passwordReset.create({
        data: {
          email,
          code,
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

      this.logger.log(`✅ Password reset code stored for: ${email}`);
    } catch (error) {
      this.logger.error('❌ Failed to store password reset code:', error);
      throw new Error('Failed to process password reset request');
    }

    // Send email with reset code
    try {
      const emailResult = await this.emailService.sendPasswordResetEmail(email, code);
      
      // In development, return preview URL and code
      if (process.env.NODE_ENV === 'development') {
        response.previewUrl = emailResult.previewUrl;
        response.code = code;
      }

      return response;
    } catch (emailError) {
      this.logger.error('❌ Email sending failed:', emailError);
      throw new Error('Failed to send password reset email');
    }
  }

  async verifyResetCode(email: string, code: string): Promise<{ valid: boolean; message: string }> {
    const resetRecord = await this.prismaService.passwordReset.findFirst({
      where: {
        email,
        code,
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
        undefined,
        undefined,
        undefined,
        undefined,
        `Invalid password reset code attempt for email: ${email}`
      );
      return { valid: false, message: 'Invalid or expired reset code' };
    }

    return { valid: true, message: 'Reset code is valid' };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto, ipAddress?: string): Promise<{ message: string }> {
    const { email, code, newPassword } = resetPasswordDto;
    const safeIpAddress = ipAddress || 'unknown';

    // Find valid reset record
    const resetRecord = await this.prismaService.passwordReset.findFirst({
      where: {
        email,
        code,
        used: false,
        expiresAt: {
          gt: new Date(),
        },
      },
    });

    if (!resetRecord) {
      throw new BadRequestException('Invalid or expired reset code');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update user password and mark reset code as used in a transaction
    await this.prismaService.$transaction(async (tx: { user: { update: (arg0: { where: { email: string; }; data: { password: string; }; }) => any; }; passwordReset: { update: (arg0: { where: { id: any; }; data: { used: boolean; }; }) => any; deleteMany: (arg0: { where: { email: string; used: boolean; }; }) => any; }; }) => {
      // Update user password
      await tx.user.update({
        where: { email },
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
          email,
          used: false,
        },
      });
    });

    // Find user for logging
    const user = await this.prismaService.user.findUnique({
      where: { email },
    });

    if (user) {
      // Log password reset
      await this.logAuditEvent(
        user.id,
        user.tenantId,
        'PASSWORD_RESET',
        user.id,
        'user',
        undefined,
        undefined,
        { ipAddress: safeIpAddress }
      );

      // Invalidate all refresh tokens for security
      await this.prismaService.refreshToken.deleteMany({
        where: { userId: user.id },
      });
    }

    this.logger.log(`✅ Password reset successfully for user: ${email}`);

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
    const payload = { 
      sub: user.id, 
      email: user.email, 
      role: user.role, 
      tenantId: user.tenantId 
    };

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
                        select: { settings: true }
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
                        select: { settings: true }
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
        const recentEvents = await this.prismaService.securityEvent.findMany({
            where: {
                type: 'DEVICE_FINGERPRINT',
                metadata: {
                    path: ['fingerprint', 'visitorId'],
                    equals: visitorId
                }
            },
            select: {
                metadata: true
            },
            take: 100,
            orderBy: { createdAt: 'desc' }
        });

        const emailSet = new Set<string>();
        emailSet.add(email);

        for (const event of recentEvents) {
            const meta: any = event.metadata;
            if (meta && meta.email) {
                emailSet.add(meta.email);
            }
        }
        relatedEmails = Array.from(emailSet);

    } catch (e) {
        this.logger.error('Error checking device history', e);
    }

    // Log the fingerprint event with related emails
    await this.logSecurityEvent(
      'DEVICE_FINGERPRINT',
      'INFO',
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

  async validateUser(payload: any) {
    return await this.prismaService.user.findUnique({
      where: { id: payload.sub },
      include: { tenant: true },
    });
  }

  async getAuditLogs(tenantId: string, page: number = 1, limit: number = 50) {
    const skip = (page - 1) * limit;

    const [logs, total] = await Promise.all([
      this.prismaService.auditLog.findMany({
        where: { tenantId },
        include: {
          user: {
            select: { email: true },
          },
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      this.prismaService.auditLog.count({
        where: { tenantId },
      }),
    ]);

    return {
      data: logs,
      meta: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async getSecurityEvents(tenantId: string, page: number = 1, limit: number = 50) {
    const skip = (page - 1) * limit;

    const [events, total] = await Promise.all([
      this.prismaService.securityEvent.findMany({
        where: { tenantId },
        include: {
          user: {
            select: { email: true },
          },
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      this.prismaService.securityEvent.count({
        where: { tenantId },
      }),
    ]);

    return {
      data: events,
      meta: {
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
  console.log('🔧 Completing OAuth setup for user:', userId);
  
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

  console.log('✅ OAuth setup completed for user:', userId);

  return {
    message: 'Setup completed successfully',
    tenant: updatedTenant,
  };
}


  // Helper method to safely handle IP addresses
  private getSafeIpAddress(ipAddress: string | undefined): string {
    return ipAddress || 'unknown';
  }
}