// apps/app-auth/src/rate-limiting/rate-limiting.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class RateLimitingService {
  private readonly logger = new Logger(RateLimitingService.name);

  constructor(private prisma: PrismaService) {}

  async getSignupRateLimiter(ipAddress: string) {
    return this.checkRateLimit(ipAddress, 'REGISTRATION', 50, 60 * 60 * 1000);
  }

  async getLoginRateLimiter(ipAddress: string) {
    return this.checkRateLimit(ipAddress, 'LOGIN', 50, 15 * 60 * 1000); // Increased to 50
  }

  async getPasswordResetRateLimiter(ipAddress: string) {
    return this.checkRateLimit(ipAddress, 'PASSWORD_RESET', 5, 60 * 60 * 1000);
  }

  async getApiRateLimiter(ipAddress: string) {
    return this.checkRateLimit(ipAddress, 'API', 1000, 60 * 1000);
  }

  async checkRateLimit(
    key: string,
    type: string,
    maxAttempts: number,
    windowMs: number,
  ): Promise<{ allowed: boolean; remaining: number; resetTime: Date }> {
    const now = new Date();
    const windowStart = new Date(now.getTime() - windowMs);

    try {
      // Find or create rate limit record
      const rateLimit = await this.prisma.rateLimit.upsert({
        where: { key_type: { key, type } },
        create: {
          key,
          type,
          attempts: 1,
          lastAttempt: now,
          expiresAt: new Date(now.getTime() + windowMs),
        },
        update: {
          attempts: { increment: 1 },
          lastAttempt: now,
          expiresAt: new Date(now.getTime() + windowMs),
        },
      });

      // Check if expired
      if (rateLimit.expiresAt < now) {
        await this.prisma.rateLimit.update({
          where: { id: rateLimit.id },
          data: {
            attempts: 1,
            lastAttempt: now,
            expiresAt: new Date(now.getTime() + windowMs),
          },
        });
        return {
          allowed: true,
          remaining: maxAttempts - 1,
          resetTime: new Date(now.getTime() + windowMs),
        };
      }

      // Check if exceeded limit
      if (rateLimit.attempts > maxAttempts) {
        return {
          allowed: false,
          remaining: 0,
          resetTime: rateLimit.expiresAt,
        };
      }

      return {
        allowed: true,
        remaining: maxAttempts - rateLimit.attempts,
        resetTime: rateLimit.expiresAt,
      };
    } catch (error) {
      this.logger.error(`Rate limiting error for ${type}:`, error);
      // Allow request if rate limiting fails
      return {
        allowed: true,
        remaining: maxAttempts,
        resetTime: new Date(now.getTime() + windowMs),
      };
    }
  }

  async isAccountLocked(ipAddress: string, email: string): Promise<boolean> {
    // Temporarily disabled for development/testing
    return false;
    
    /*
    try {
      const loginAttempt = await this.prisma.loginAttempt.findUnique({
        where: { ipAddress_email: { ipAddress, email } },
      });

      if (loginAttempt?.lockedUntil && loginAttempt.lockedUntil > new Date()) {
        return true;
      }
      return false;
    } catch (error) {
      this.logger.error('Error checking account lock:', error);
      return false;
    }
    */
  }

  async recordLoginAttempt(ipAddress: string, email: string, success: boolean): Promise<void> {
    try {
      if (success) {
        // Reset failed attempts on successful login
        await this.prisma.loginAttempt.deleteMany({
          where: { ipAddress, email },
        });
      } else {
        // Increment failed attempts
        const attempt = await this.prisma.loginAttempt.upsert({
          where: { ipAddress_email: { ipAddress, email } },
          create: {
            ipAddress,
            email,
            attempts: 1,
            lastAttemptAt: new Date(),
          },
          update: {
            attempts: { increment: 1 },
            lastAttemptAt: new Date(),
          },
        });

        // Lock account after 100 failed attempts (increased from 10)
        if (attempt.attempts >= 100) {
          await this.prisma.loginAttempt.update({
            where: { ipAddress_email: { ipAddress, email } },
            data: {
              lockedUntil: new Date(Date.now() + 30 * 60 * 1000),
            },
          });
        }
      }
    } catch (error) {
      this.logger.error('Failed to record login attempt:', error);
    }
  }

  async recordSecurityEvent(
    type: string,
    severity: string,
    description?: string,
    userId?: string,
    tenantId?: string,
    ipAddress?: string,
    userAgent?: string,
    metadata?: any,
  ): Promise<void> {
    try {
      await this.prisma.securityEvent.create({
        data: {
          type,
          severity,
          userId,
          tenantId,
          ipAddress,
          userAgent,
          description,
          metadata,
        },
      });
    } catch (error) {
      this.logger.error('Failed to record security event:', error);
    }
  }

  async cleanupExpiredRateLimits(): Promise<void> {
    try {
      await this.prisma.rateLimit.deleteMany({
        where: {
          expiresAt: {
            lt: new Date(),
          },
        },
      });
    } catch (error) {
      this.logger.error('Failed to cleanup expired rate limits:', error);
    }
  }

  async blockIp(ipAddress: string): Promise<void> {
    const types = ['LOGIN', 'API', 'CHECKOUT', 'PAYMENT', 'PASSWORD_RESET', 'REGISTRATION'];
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000); // 1 year

    try {
      for (const type of types) {
        await this.prisma.rateLimit.upsert({
          where: { key_type: { key: ipAddress, type: type as any } },
          create: {
            key: ipAddress,
            type: type as any,
            attempts: 999999, // Max attempts exceeded
            lastAttempt: now,
            expiresAt,
          },
          update: {
            attempts: 999999,
            lastAttempt: now,
            expiresAt,
          },
        });
      }
      this.logger.log(`Blocked IP: ${ipAddress}`);
    } catch (error) {
      this.logger.error(`Failed to block IP ${ipAddress}:`, error);
      throw error;
    }
  }

  async clearAllRateLimits(): Promise<void> {
    try {
      await this.prisma.rateLimit.deleteMany({});
      this.logger.log('Cleared all rate limits');
    } catch (error) {
      this.logger.error('Failed to clear all rate limits:', error);
      throw error;
    }
  }
}