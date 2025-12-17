import { 
  Controller, 
  Post, 
  Body, 
  HttpCode, 
  HttpStatus, 
  Get, 
  Put,
  Query,
  Param,
  UseGuards, 
  Req,
  Request,
  Res,
  ForbiddenException,
  UnauthorizedException,
  InternalServerErrorException,
  NotFoundException,
  BadRequestException,
  Logger
} from '@nestjs/common';
import { Response } from 'express';
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

  /**
   * Get cookie options for setting authentication tokens
   * Supports cross-subdomain cookies in production
   */
  private getCookieOptions() {
    const isProduction = process.env.NODE_ENV === 'production';
    // For production, set domain to allow cookies across subdomains (e.g., .saeaa.com, .saeaa.net)
    // This allows cookies to work for store.saeaa.com, app.saeaa.com, etc.
    const cookieDomain = isProduction 
      ? (process.env.COOKIE_DOMAIN || '.saeaa.net') // Default to .saeaa.net for cross-subdomain support
      : undefined; // No domain in development (localhost)
    
    return {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax' as const,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
      ...(cookieDomain && { domain: cookieDomain }), // Only set domain in production
    };
  }

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

  @Get('security-events')
  async getSecurityEvents(
    @Query('page') page?: string,
    @Query('limit') limit?: string,
  ) {
    try {
      const result = await this.authService.getSecurityEvents({
        page: page ? parseInt(page) : 1,
        limit: limit ? parseInt(limit) : 50,
      });
      return result;
    } catch (error) {
      this.logger.error('Failed to fetch security events:', error);
      return { logs: [], pagination: { total: 0, page: 1, limit: 50, totalPages: 0 } };
    }
  }

  @Get('audit-logs')
  async getAuditLogs(
    @Query('page') page?: string,
    @Query('limit') limit?: string,
  ) {
    try {
      const result = await this.authService.getAuditLogs({
        page: page ? parseInt(page) : 1,
        limit: limit ? parseInt(limit) : 50,
      });
      return result;
    } catch (error) {
      this.logger.error('Failed to fetch audit logs:', error);
      return { logs: [], pagination: { total: 0, page: 1, limit: 50, totalPages: 0 } };
    }
  }

  @Post('signup')
  async signUp(@Req() req: any, @Res({ passthrough: true }) res: Response, @Body() signUpDto: any) {
    const ipAddress = req.ip || req.connection?.remoteAddress || 'unknown';
    const fingerprint = signUpDto.fingerprint;
    
    try {
      this.logger.log(`Signup attempt: ${JSON.stringify(signUpDto)}`);
      const result = await this.authService.signUp(signUpDto, fingerprint);
      this.logger.log(`Signup successful for: ${signUpDto.email}`);
      
      // Set cookies for tokens
      const cookieOptions = this.getCookieOptions();
      res.cookie('accessToken', result.accessToken, cookieOptions);
      res.cookie('refreshToken', result.refreshToken, cookieOptions);
      
      return result;
    } catch (error) {
      this.logger.error(`Signup failed for ${signUpDto.email}:`, error);
      throw error;
    }
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Req() req: any, @Res({ passthrough: true }) res: Response, @Body() loginDto: any) {
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
      
      // Set cookies for tokens
      const cookieOptions = this.getCookieOptions();
      res.cookie('accessToken', result.accessToken, cookieOptions);
      res.cookie('refreshToken', result.refreshToken, cookieOptions);
      
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
  async refreshTokens(@Req() req: any, @Res({ passthrough: true }) res: Response, @Body('refreshToken') refreshToken?: string) {
    // Try to get refresh token from cookie if not in body
    const token = refreshToken || req.cookies?.refreshToken;
    if (!token) {
      throw new UnauthorizedException('Refresh token is required');
    }
    
    const result = await this.authService.refreshTokens(token);
    
    // Update cookies with new tokens
    const cookieOptions = this.getCookieOptions();
    res.cookie('accessToken', result.accessToken, cookieOptions);
    res.cookie('refreshToken', result.refreshToken, cookieOptions);
    
    return result;
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
        tenant: {
          select: {
            id: true,
            name: true,
            subdomain: true,
          },
        },
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Flatten tenant info for frontend convenience
    return { 
      user: {
        ...user,
        tenantName: user.tenant?.name,
        tenantSubdomain: user.tenant?.subdomain,
        tenant: undefined, // Remove nested object
      }
    };
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  async logout(@Res({ passthrough: true }) res: Response) {
    // Clear cookies
    res.cookie('accessToken', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      expires: new Date(0),
      path: '/',
    });
    res.cookie('refreshToken', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      expires: new Date(0),
      path: '/',
    });
    
    return { message: 'Logged out successfully' };
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

  @Get('verify-reset-token')
  @HttpCode(HttpStatus.OK)
  async verifyResetToken(@Query('token') token: string) {
    if (!token) {
      throw new BadRequestException('Token is required');
    }
    return this.authService.verifyResetToken(token);
  }


  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Req() req: any, @Res({ passthrough: true }) res: Response, @Body() body: { email: string; code: string }) {
    try {
      const result = await this.authService.verifySignupCode(body.email, body.code);
      
      if (result.valid && result.tokens) {
        // Set cookies for tokens
        const cookieOptions = this.getCookieOptions();
        res.cookie('accessToken', result.tokens.accessToken, cookieOptions);
        res.cookie('refreshToken', result.tokens.refreshToken, cookieOptions);
      }
      
      return result;
    } catch (error) {
      this.logger.error(`Email verification failed for ${body.email}:`, error);
      throw error;
    }
  }

  @Post('resend-verification')
  @HttpCode(HttpStatus.OK)
  async resendVerification(@Body() body: { email: string }) {
    try {
      await this.authService.resendVerificationCode(body.email);
      return {
        message: 'Verification code resent successfully',
        email: body.email,
      };
    } catch (error) {
      this.logger.error(`Resend verification failed for ${body.email}:`, error);
      throw error;
    }
  }

  @Post('verify-reset-code')
  @HttpCode(HttpStatus.OK)
  async verifyResetCode(@Body() verifyCodeDto: { email: string; code: string }) {
    try {
      const result = await this.authService.verifyResetCode(verifyCodeDto.email, verifyCodeDto.code);
      return result;
    } catch (error) {
      this.logger.error(`Reset code verification failed for ${verifyCodeDto.email}:`, error);
      throw error;
    }
  }

  @Post('test-email')
  async testEmail(@Body() body: { email: string }) {
    try {
      // Test with verification email (same as signup flow)
      const result = await this.emailService.sendVerificationEmail(body.email, '123456');
      return {
        success: true,
        message: result.isTestEmail 
          ? 'Test email sent to preview URL (Gmail SMTP not working)' 
          : 'Test email sent to real inbox',
        previewUrl: result.previewUrl,
        messageId: result.messageId,
        isTestEmail: result.isTestEmail,
        code: result.code,
        note: result.isTestEmail 
          ? `Gmail SMTP is not working. Email sent to preview URL only. Fix Gmail App Password to send real emails to ${body.email}.` 
          : `Email should arrive in ${body.email}'s inbox`
      };
    } catch (error) {
      this.logger.error('Test email failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  @Get('users')
  @UseGuards(JwtAuthGuard)
  async getUsers() {
    try {
      const users = await this.authService['prismaService'].user.findMany({
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          marketLimit: true,
          tenantId: true,
          tenant: {
            select: {
              name: true,
              subdomain: true
            }
          },
          userTenants: {
            where: { isOwner: true },
            select: { id: true }
          }
        }
      });
      
      // Add currentMarkets count to each user
      const usersWithMarketCount = users.map((user: any) => ({
        ...user,
        currentMarkets: user.userTenants?.length || 0,
        userTenants: undefined // Remove from response
      }));
      
      return { users: usersWithMarketCount };
    } catch (error) {
      return { error: error };
    }
  }

  @Get('error-logs')
  async getErrorLogs(
    @Query('page') page?: string,
    @Query('limit') limit?: string,
  ) {
    try {
      return await this.authService.getErrorLogs({
        page: page ? parseInt(page) : 1,
        limit: limit ? parseInt(limit) : 50,
      });
    } catch (error) {
      this.logger.error('Failed to fetch error logs:', error);
      return { logs: [], pagination: { total: 0, page: 1, limit: 50, totalPages: 0 } };
    }
  }

  @Post('error-logs')
  async createErrorLog(@Body() body: { message: string; stack?: string; context?: string; severity?: string; userId?: string; tenantId?: string; metadata?: any }) {
    try {
      await this.authService.logErrorEvent({
        message: body.message,
        stack: body.stack,
        context: body.context,
        severity: (body.severity as any) || 'HIGH',
        userId: body.userId,
        tenantId: body.tenantId,
        metadata: body.metadata,
      });
      return { success: true };
    } catch (error) {
      this.logger.error('Failed to create error log:', error);
      return { success: false, error: String(error) };
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

  // ==================== MARKET MANAGEMENT ====================

  @UseGuards(JwtAuthGuard)
  @Get('markets')
  async getUserMarkets(@Request() req: any) {
    try {
      this.logger.debug('getUserMarkets - req.user:', JSON.stringify(req.user));
      if (!req.user) {
        this.logger.error('getUserMarkets - req.user is undefined');
        throw new UnauthorizedException('User not authenticated - req.user is undefined');
      }
      if (!req.user.id) {
        this.logger.error('getUserMarkets - req.user.id is undefined', JSON.stringify(req.user));
        throw new UnauthorizedException('User not authenticated - req.user.id is undefined');
      }
      return await this.authService.getUserMarkets(req.user.id);
    } catch (error) {
      this.logger.error('Error in getUserMarkets:', error);
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new InternalServerErrorException(`Failed to get user markets: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  @UseGuards(JwtAuthGuard)
  @Get('markets/limit')
  async getUserMarketLimit(@Request() req: any) {
    if (!req.user || !req.user.id) {
      throw new UnauthorizedException('User not authenticated');
    }
    return this.authService.getUserMarketLimit(req.user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Post('markets/switch')
  async switchActiveMarket(
    @Request() req: any, 
    @Body() body: { tenantId: string },
    @Res({ passthrough: true }) res: Response
  ) {
    if (!req.user || !req.user.id) {
      throw new UnauthorizedException('User not authenticated');
    }
    
    const result = await this.authService.switchActiveTenant(req.user.id, body.tenantId);
    
    // Get the updated user with the new tenantId
    const user = await this.authService['prismaService'].user.findUnique({
      where: { id: req.user.id },
      include: { tenant: true }
    });
    
    if (!user) {
      throw new NotFoundException('User not found');
    }
    
    // Generate new tokens with the updated tenantId
    const tokens = await this.authService['generateTokens'](user);
    
    // Set cookies with new tokens
    const cookieOptions = this.getCookieOptions();
    res.cookie('accessToken', tokens.accessToken, cookieOptions);
    res.cookie('refreshToken', tokens.refreshToken, cookieOptions);
    
    return {
      ...result,
      ...tokens,
      tenantName: user.tenant?.name,
      tenantSubdomain: user.tenant?.subdomain
    };
  }

  @UseGuards(JwtAuthGuard)
  @Get('markets/can-create')
  async canCreateMarket(@Request() req: any) {
    try {
      this.logger.debug('canCreateMarket - req.user:', JSON.stringify(req.user));
      if (!req.user) {
        this.logger.error('canCreateMarket - req.user is undefined');
        throw new UnauthorizedException('User not authenticated - req.user is undefined');
      }
      if (!req.user.id) {
        this.logger.error('canCreateMarket - req.user.id is undefined', JSON.stringify(req.user));
        throw new UnauthorizedException('User not authenticated - req.user.id is undefined');
      }
      return await this.authService.canCreateMarket(req.user.id);
    } catch (error) {
      this.logger.error('Error in canCreateMarket:', error);
      if (error instanceof UnauthorizedException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerErrorException(`Failed to check market creation: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  @Post('markets/link')
  async linkUserToTenant(@Body() body: { userId: string; tenantId: string }) {
    return this.authService.linkUserToTenant(body.userId, body.tenantId, true);
  }

  @UseGuards(JwtAuthGuard)
  @Post('markets/create')
  async createTenantAndLink(@Request() req: any, @Body() body: { id: string; name: string; subdomain: string; plan?: string; status?: string }) {
    return this.authService.createTenantAndLink(req.user.id, body);
  }

  // Admin endpoint to update market limit
  @Put('users/:userId/market-limit')
  @UseGuards(JwtAuthGuard)
  async updateMarketLimit(@Param('userId') userId: string, @Body() body: { limit: number }) {
    return this.authService.updateMarketLimit(userId, body.limit);
  }
}