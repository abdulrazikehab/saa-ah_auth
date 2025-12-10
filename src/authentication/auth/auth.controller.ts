import { 
  Controller, 
  Post, 
  Body, 
  HttpCode, 
  HttpStatus, 
  Get, 
  Put,
  UseGuards, 
  Req,
  Request,
  ForbiddenException,
  UnauthorizedException,
  InternalServerErrorException,
  NotFoundException,
  Logger
} from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { EmailService } from '../../email/email.service';
import { RateLimitingService } from '../../rate-limiting/rate-limiting.service';
import { JwtAuthGuard } from '../guard/jwt-auth.guard';

@UseGuards(ThrottlerGuard)
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private authService: AuthService,
    private emailService: EmailService,
    private rateLimitingService: RateLimitingService,
  ) {}

  @Get('test')
  test() {
    return { message: 'Auth controller is working!' };
  }

  @Get('test-db')
  async testDb() {
    try {
      const userCount = await this.authService.testDatabaseConnection();
      return { 
        message: 'Database connection successful',
        userCount 
      };
    } catch (error) {
      return { 
        message: 'Database connection failed',
        error: error 
      };
    }
  }

  @Get('test-security-event')
  async testSecurityEvent(@Req() req: any) {
    const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress || '8.8.8.8';
    const userAgent = req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
    
    try {
      const result = await this.authService.createTestSecurityEvent(ipAddress, userAgent);
      return { 
        message: 'Test security event created successfully',
        ...result
      };
    } catch (error) {
      this.logger.error('Failed to create test security event:', error);
      return { 
        message: 'Failed to create test security event',
        error: String(error)
      };
    }
  }

  @Post('signup')
  async signUp(@Req() req: any, @Body() signUpDto: any) {
    const ipAddress = req.ip || req.connection?.remoteAddress || 'unknown';
    const fingerprint = signUpDto.fingerprint;
    
    try {
      this.logger.log(`Signup attempt: ${JSON.stringify(signUpDto)}`);
      const result = await this.authService.signUp(signUpDto, fingerprint);
      this.logger.log(`Signup successful for: ${signUpDto.email}`);
      return result;
    } catch (error) {
      this.logger.error(`Signup failed for ${signUpDto.email}:`, error);
      throw error;
    }
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Req() req: any, @Body() loginDto: any) {
    const ipAddress = req.ip || req.connection?.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'];
    const fingerprint = loginDto.fingerprint;
    const identifier = loginDto.email || loginDto.username || 'unknown';
    
    // Check if account is locked
    const isLocked = await this.rateLimitingService.isAccountLocked(ipAddress, identifier);
    if (isLocked) {
      throw new ForbiddenException('Account temporarily locked due to too many failed attempts. Please try again later.');
    }

    try {
      const result = await this.authService.login(loginDto, ipAddress, userAgent, fingerprint);
      await this.rateLimitingService.recordLoginAttempt(ipAddress, identifier, true);
      return result;
    } catch (error) {
      this.logger.error(`Login failed for ${identifier}:`, error);
      await this.rateLimitingService.recordLoginAttempt(ipAddress, identifier, false);
      throw error;
    }
  }

  /**
   * Recover email using recovery ID (no password needed)
   * Returns masked email address
   */
  @Post('recover-email')
  @HttpCode(HttpStatus.OK)
  async recoverEmail(@Body() body: { recoveryId: string }) {
    if (!body.recoveryId) {
      throw new ForbiddenException('Recovery ID is required');
    }
    return this.authService.recoverEmailByRecoveryId(body.recoveryId);
  }

  /**
   * Login using recovery ID and password
   */
  @Post('login-recovery')
  @HttpCode(HttpStatus.OK)
  async loginWithRecoveryId(
    @Req() req: any,
    @Body() body: { recoveryId: string; password: string }
  ) {
    if (!body.recoveryId || !body.password) {
      throw new ForbiddenException('Recovery ID and password are required');
    }
    const ipAddress = req.ip || req.connection?.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'];
    return this.authService.loginWithRecoveryId(body.recoveryId, body.password, ipAddress, userAgent);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshTokens(@Body('refreshToken') refreshToken: string) {
    return this.authService.refreshTokens(refreshToken);
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getMe(@Request() req: any) {
    const userId = req.user?.userId || req.user?.id;
    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }
    
    const user = await this.authService['prismaService'].user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        role: true,
        tenantId: true,
        avatar: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return { user };
  }

  @Put('profile')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async updateProfile(
    @Request() req: any,
    @Body() updateData: { name?: string; avatar?: string }
  ) {
    const userId = req.user?.userId || req.user?.id;
    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }

    try {
      const updatedUser = await this.authService['prismaService'].user.update({
        where: { id: userId },
        data: {
          avatar: updateData.avatar,
        },
        select: {
          id: true,
          email: true,
          role: true,
          tenantId: true,
          avatar: true,
          createdAt: true,
          updatedAt: true,
        },
      });

      this.logger.log(`User profile updated: ${userId}`);
      return updatedUser;
    } catch (error) {
      this.logger.error(`Error updating user profile: ${error}`);
      throw new InternalServerErrorException('Failed to update profile');
    }
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Req() req: any, @Body() forgotPasswordDto: any) {
    const ipAddress = req.ip || req.connection?.remoteAddress || 'unknown';
    
    // Check rate limit for password reset
    // const rateLimit = await this.rateLimitingService.getPasswordResetRateLimiter(ipAddress);
    // if (!rateLimit.allowed) {
    //   await this.rateLimitingService.recordSecurityEvent(
    //     'RATE_LIMIT_EXCEEDED',
    //     'MEDIUM',
    //     `Password reset rate limit exceeded for IP: ${ipAddress}`,
    //     undefined,
    //     undefined,
    //     ipAddress,
    //     req.headers['user-agent'],
    //   );
    //   throw new ForbiddenException('Too many password reset attempts. Please try again later.');
    // }

    return this.authService.forgotPassword(forgotPasswordDto, ipAddress);
  }

  /**
   * Send password reset email using recovery ID
   * This allows users to reset password without knowing their email
   */
  @Post('send-reset-by-recovery')
  @HttpCode(HttpStatus.OK)
  async sendResetByRecoveryId(@Body() body: { recoveryId: string }) {
    if (!body.recoveryId) {
      throw new ForbiddenException('Recovery ID is required');
    }
    return this.authService.sendPasswordResetByRecoveryId(body.recoveryId);
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Req() req: any, @Body() resetPasswordDto: any) {
    const ipAddress = req.ip || req.connection?.remoteAddress || 'unknown';
    return this.authService.resetPassword(resetPasswordDto, ipAddress);
  }


  @Post('verify-reset-code')
  @HttpCode(HttpStatus.OK)
  async verifyResetCode(@Body() verifyCodeDto: any) {
    return this.authService.verifyResetCode(verifyCodeDto.email, verifyCodeDto.code);
  }

  @Post('test-email')
  async testEmail(@Body() body: { email: string }) {
    try {
      const result = await this.emailService.sendPasswordResetEmail(body.email, '123456');
      return {
        success: true,
        message: 'Test email sent successfully',
        previewUrl: result.previewUrl,
        messageId: result.messageId
      };
    } catch (error) {
      return {
        success: false,
        error: error
      };
    }
  }

  @Get('users')
  async getUsers() {
    try {
      const users = await this.authService['prismaService'].user.findMany({
        select: {
          id: true,
          email: true,
          role: true,
          tenant: {
            select: {
              name: true,
              subdomain: true
            }
          }
        }
      });
      return { users };
    } catch (error) {
      return { error: error };
    }
  }

  @Get('audit-logs')
  @UseGuards(JwtAuthGuard)
  async getAuditLogs(@Req() req: any) {
    try {
      const ipAddress = req.ip || req.connection?.remoteAddress || 'unknown';
      
      // Get user from token to filter by tenant
      const user = (req as any).user;
      
      let remaining = 1000;

      // Rate limit audit log access (Skip for SUPER_ADMIN)
      if (user?.role !== 'SUPER_ADMIN') {
        const rateLimit = await this.rateLimitingService.getApiRateLimiter(ipAddress);
        remaining = rateLimit.remaining;
        if (!rateLimit.allowed) {
          this.logger.debug(`Audit log access rate limit exceeded for IP: ${ipAddress}`);
          throw new Error('Rate limit exceeded');
        }
      }
      let whereClause = {};

      // If user is not SUPER_ADMIN, filter by tenantId
      if (user?.role !== 'SUPER_ADMIN' && user?.tenantId) {
        whereClause = { tenantId: user.tenantId };
        this.logger.debug(`Filtering audit logs for tenantId: ${user.tenantId}`);
      } else if (user?.role === 'SUPER_ADMIN') {
        this.logger.debug('SUPER_ADMIN accessing all audit logs.');
      } else {
        this.logger.debug('User not authenticated or tenantId missing for audit log access.');
      }

      // Fetch SecurityEvents instead of AuditLogs to show security alerts
      const events = await this.authService['prismaService'].securityEvent.findMany({
        where: whereClause,
        take: 50,
        orderBy: { createdAt: 'desc' },
        include: {
          user: {
            select: { email: true }
          },
          tenant: {
            select: { name: true }
          }
        }
      });
      
      // Map to frontend expected format
      const logs = events.map((event: any) => ({
        id: event.id,
        action: event.type,
        details: event.description,
        ipAddress: event.ipAddress,
        severity: event.severity,
        createdAt: event.createdAt,
        user: event.user,
        tenant: event.tenant,
        metadata: event.metadata
      }));
      
      return { logs, remaining };
    } catch (error) {
      return { error: error };
    }
  }

  @Post('backfill-usernames')
  async backfillUsernames() {
    try {
      const users = await this.authService['prismaService'].user.findMany({
        where: { username: null },
      });

      let updatedCount = 0;
      for (const user of users) {
        const username = user.email.split('@')[0].toLowerCase();
        
        // Check if username is taken
        const existing = await this.authService['prismaService'].user.findFirst({
          where: { username, id: { not: user.id } }
        });

        if (!existing) {
          await this.authService['prismaService'].user.update({
            where: { id: user.id },
            data: { username },
          });
          updatedCount++;
        }
      }

      return { 
        message: 'Usernames backfilled successfully', 
        total: users.length,
        updated: updatedCount 
      };
    } catch (error) {
      this.logger.error('Failed to backfill usernames:', error);
      throw new InternalServerErrorException('Failed to backfill usernames');
    }
  }
}