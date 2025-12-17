import { Controller, Post, Delete, Put, Get, Body, HttpCode, HttpStatus, Query, Logger } from '@nestjs/common';
import { RateLimitingService } from '../rate-limiting/rate-limiting.service';
import { PrismaService } from '../prisma/prisma.service';

@Controller('admin')
export class AdminController {
  private readonly logger = new Logger(AdminController.name);

  constructor(
    private rateLimitingService: RateLimitingService,
    private prismaService: PrismaService,
  ) {}

  // Rate Limit Management
  @Delete('clear-rate-limits')
  @HttpCode(HttpStatus.OK)
  async clearRateLimits(@Query('type') type?: string) {
    if (type) {
      await this.prismaService.rateLimit.deleteMany({
        where: { type: type as any },
      });
      this.logger.log(`Cleared rate limits for type: ${type}`);
      return { message: `Rate limits for type ${type} cleared successfully` };
    }
    await this.rateLimitingService.clearAllRateLimits();
    this.logger.log('Cleared all rate limits');
    return { message: 'All rate limits cleared successfully' };
  }

  @Get('rate-limits/stats')
  async getRateLimitStats() {
    const stats = await this.prismaService.rateLimit.groupBy({
      by: ['type'],
      _count: { id: true },
    });
    const total = await this.prismaService.rateLimit.count();
    return {
      total,
      byType: stats.map(s => ({ type: s.type, count: s._count.id })),
    };
  }

  @Post('block-ip')
  @HttpCode(HttpStatus.OK)
  async blockIp(@Body() body: { ip: string }) {
    await this.rateLimitingService.blockIp(body.ip);
    return { message: `IP ${body.ip} has been blocked` };
  }

  @Delete('unblock-ip')
  @HttpCode(HttpStatus.OK)
  async unblockIp(@Body() body: { ip: string }) {
    await this.prismaService.rateLimit.deleteMany({
      where: {
        key: body.ip,
        attempts: 999999, // Blocked IPs have this value
      },
    });
    this.logger.log(`Unblocked IP: ${body.ip}`);
    return { message: `IP ${body.ip} has been unblocked` };
  }

  // Login Attempts Management
  @Delete('clear-login-attempts')
  @HttpCode(HttpStatus.OK)
  async clearLoginAttempts(@Query('email') email?: string, @Query('ip') ip?: string) {
    const where: any = {};
    if (email) where.email = email;
    if (ip) where.ipAddress = ip;

    const deleted = await this.prismaService.loginAttempt.deleteMany({ where });
    this.logger.log(`Cleared ${deleted.count} login attempts`);
    return { message: `Cleared ${deleted.count} login attempt(s)`, count: deleted.count };
  }

  // Security Events Management
  @Delete('clear-security-events')
  @HttpCode(HttpStatus.OK)
  async clearSecurityEvents(@Query('severity') severity?: string) {
    const where: any = {};
    if (severity) where.severity = severity;

    const deleted = await this.prismaService.securityEvent.deleteMany({ where });
    this.logger.log(`Cleared ${deleted.count} security events`);
    return { message: `Cleared ${deleted.count} security event(s)`, count: deleted.count };
  }

  // Password Reset Management
  @Delete('clear-password-resets')
  @HttpCode(HttpStatus.OK)
  async clearPasswordResets(@Query('email') email?: string, @Query('used') used?: string) {
    const where: any = {};
    if (email) where.email = email;
    if (used !== undefined) where.used = used === 'true';

    const deleted = await this.prismaService.passwordReset.deleteMany({ where });
    this.logger.log(`Cleared ${deleted.count} password reset records`);
    return { message: `Cleared ${deleted.count} password reset record(s)`, count: deleted.count };
  }

  // User Management
  @Delete('clear-users')
  @HttpCode(HttpStatus.OK)
  async clearUsers(@Query('email') email?: string, @Query('tenantId') tenantId?: string) {
    const where: any = {};
    if (email) where.email = email;
    if (tenantId) where.tenantId = tenantId;

    const deleted = await this.prismaService.user.deleteMany({ where });
    this.logger.log(`Cleared ${deleted.count} users`);
    return { message: `Cleared ${deleted.count} user(s)`, count: deleted.count };
  }

  // Rate Limit Configuration
  @Put('rate-limit-config')
  @HttpCode(HttpStatus.OK)
  async updateRateLimitConfig(@Body() config: {
    loginMaxAttempts?: number;
    loginWindowMs?: number;
    signupMaxAttempts?: number;
    signupWindowMs?: number;
    passwordResetMaxAttempts?: number;
    passwordResetWindowMs?: number;
  }) {
    this.logger.log('⚠️ Rate limit config update requested:', config);
    
    // Update environment variables in memory (will be reset on server restart)
    // For persistence, these should be set in .env file
    if (config.loginMaxAttempts !== undefined) {
      process.env.LOGIN_MAX_ATTEMPTS = String(config.loginMaxAttempts);
      this.logger.log(`✅ LOGIN_MAX_ATTEMPTS set to: ${config.loginMaxAttempts}`);
    }
    if (config.loginWindowMs !== undefined) {
      process.env.LOGIN_WINDOW_MS = String(config.loginWindowMs);
      this.logger.log(`✅ LOGIN_WINDOW_MS set to: ${config.loginWindowMs}ms (${Math.floor(config.loginWindowMs / 60000)} minutes)`);
    }
    if (config.signupMaxAttempts !== undefined) {
      process.env.SIGNUP_MAX_ATTEMPTS = String(config.signupMaxAttempts);
      this.logger.log(`✅ SIGNUP_MAX_ATTEMPTS set to: ${config.signupMaxAttempts}`);
    }
    if (config.signupWindowMs !== undefined) {
      process.env.SIGNUP_WINDOW_MS = String(config.signupWindowMs);
      this.logger.log(`✅ SIGNUP_WINDOW_MS set to: ${config.signupWindowMs}ms (${Math.floor(config.signupWindowMs / 3600000)} hours)`);
    }
    if (config.passwordResetMaxAttempts !== undefined) {
      process.env.PASSWORD_RESET_MAX_ATTEMPTS = String(config.passwordResetMaxAttempts);
      this.logger.log(`✅ PASSWORD_RESET_MAX_ATTEMPTS set to: ${config.passwordResetMaxAttempts}`);
    }
    if (config.passwordResetWindowMs !== undefined) {
      process.env.PASSWORD_RESET_WINDOW_MS = String(config.passwordResetWindowMs);
      this.logger.log(`✅ PASSWORD_RESET_WINDOW_MS set to: ${config.passwordResetWindowMs}ms (${Math.floor(config.passwordResetWindowMs / 3600000)} hours)`);
    }
    
    return {
      message: 'Rate limit configuration updated in memory',
      warning: 'Changes are temporary. To make them permanent, add these to your .env file and restart the server:',
      envVars: {
        LOGIN_MAX_ATTEMPTS: process.env.LOGIN_MAX_ATTEMPTS,
        LOGIN_WINDOW_MS: process.env.LOGIN_WINDOW_MS,
        SIGNUP_MAX_ATTEMPTS: process.env.SIGNUP_MAX_ATTEMPTS,
        SIGNUP_WINDOW_MS: process.env.SIGNUP_WINDOW_MS,
        PASSWORD_RESET_MAX_ATTEMPTS: process.env.PASSWORD_RESET_MAX_ATTEMPTS,
        PASSWORD_RESET_WINDOW_MS: process.env.PASSWORD_RESET_WINDOW_MS,
      },
      config: await this.getRateLimitConfig(),
    };
  }

  @Get('rate-limit-config')
  async getRateLimitConfig() {
    // Return current config from environment variables or defaults
    return {
      login: {
        maxAttempts: parseInt(process.env.LOGIN_MAX_ATTEMPTS || '100', 10),
        windowMs: parseInt(process.env.LOGIN_WINDOW_MS || String(15 * 60 * 1000), 10),
      },
      signup: {
        maxAttempts: parseInt(process.env.SIGNUP_MAX_ATTEMPTS || '3', 10),
        windowMs: parseInt(process.env.SIGNUP_WINDOW_MS || String(60 * 60 * 1000), 10),
      },
      passwordReset: {
        maxAttempts: parseInt(process.env.PASSWORD_RESET_MAX_ATTEMPTS || '5', 10),
        windowMs: parseInt(process.env.PASSWORD_RESET_WINDOW_MS || String(60 * 60 * 1000), 10),
      },
    };
  }

  // Database Statistics
  @Get('stats')
  async getDatabaseStats() {
    const [
      usersCount,
      tenantsCount,
      rateLimitsCount,
      loginAttemptsCount,
      securityEventsCount,
      passwordResetsCount,
      refreshTokensCount,
    ] = await Promise.all([
      this.prismaService.user.count(),
      this.prismaService.tenant.count(),
      this.prismaService.rateLimit.count(),
      this.prismaService.loginAttempt.count(),
      this.prismaService.securityEvent.count(),
      this.prismaService.passwordReset.count(),
      this.prismaService.refreshToken.count(),
    ]);

    return {
      users: usersCount,
      tenants: tenantsCount,
      rateLimits: rateLimitsCount,
      loginAttempts: loginAttemptsCount,
      securityEvents: securityEventsCount,
      passwordResets: passwordResetsCount,
      refreshTokens: refreshTokensCount,
    };
  }

  // Clear Refresh Tokens
  @Delete('clear-refresh-tokens')
  @HttpCode(HttpStatus.OK)
  async clearRefreshTokens(@Query('userId') userId?: string) {
    const where: any = {};
    if (userId) where.userId = userId;

    const deleted = await this.prismaService.refreshToken.deleteMany({ where });
    this.logger.log(`Cleared ${deleted.count} refresh tokens`);
    return { message: `Cleared ${deleted.count} refresh token(s)`, count: deleted.count };
  }

  // Comprehensive Clear Operations
  @Delete('clear-all')
  @HttpCode(HttpStatus.OK)
  async clearAll(@Body() body: {
    rateLimits?: boolean;
    loginAttempts?: boolean;
    securityEvents?: boolean;
    passwordResets?: boolean;
    users?: boolean;
    tenants?: boolean;
    refreshTokens?: boolean;
  }) {
    const results: any = {};

    if (body.rateLimits) {
      await this.rateLimitingService.clearAllRateLimits();
      results.rateLimits = 'cleared';
    }
    if (body.loginAttempts) {
      const deleted = await this.prismaService.loginAttempt.deleteMany({});
      results.loginAttempts = deleted.count;
    }
    if (body.securityEvents) {
      const deleted = await this.prismaService.securityEvent.deleteMany({});
      results.securityEvents = deleted.count;
    }
    if (body.passwordResets) {
      const deleted = await this.prismaService.passwordReset.deleteMany({});
      results.passwordResets = deleted.count;
    }
    if (body.refreshTokens) {
      const deleted = await this.prismaService.refreshToken.deleteMany({});
      results.refreshTokens = deleted.count;
    }
    if (body.users) {
      const deleted = await this.prismaService.user.deleteMany({});
      results.users = deleted.count;
    }
    if (body.tenants) {
      const deleted = await this.prismaService.tenant.deleteMany({});
      results.tenants = deleted.count;
    }

    this.logger.log('Bulk clear operation completed:', results);
    return { message: 'Clear operations completed', results };
  }
}
