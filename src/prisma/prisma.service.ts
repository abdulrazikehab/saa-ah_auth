import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';

@Injectable()
export class PrismaService implements OnModuleInit, OnModuleDestroy {
  public prisma: any;

  constructor() {
    console.log('🔧 Auth PrismaService constructor called');
    try {
      const { PrismaClient } = require('.prisma/client');
      this.prisma = new PrismaClient({
        log: ['query', 'info', 'warn', 'error'],
      });
      
      // Register Encryption Middleware
      try {
        const { EncryptionMiddleware } = require('./prisma-encryption.middleware');
        this.prisma.$use(EncryptionMiddleware);
        console.log('✅ Encryption Middleware registered');
      } catch (e) {
        console.error('⚠️ Failed to register Encryption Middleware:', e);
      }

      console.log('✅ Auth PrismaClient created successfully');
    } catch (error) {
      console.error('❌ Failed to create Auth PrismaClient:', error);
      throw error;
    }
  }

  async onModuleInit() {
    console.log('🔧 Auth PrismaService onModuleInit called');
    try {
      await this.prisma.$connect();
      console.log('✅ Auth Prisma connected to database');
    } catch (error) {
      console.error('❌ Failed to connect to Auth database:', error);
      throw error;
    }
  }

  async onModuleDestroy() {
    await this.prisma.$disconnect();
    console.log('❌ Auth Prisma disconnected from database');
  }

  // Expose all Prisma models
  get user() {
    return this.prisma.user;
  }

  get tenant() {
    return this.prisma.tenant;
  }

   get customer() {
    return this.prisma.customer;
  }

  get refreshToken() {
    return this.prisma.refreshToken;
  }

  get passwordReset() {
    return this.prisma.passwordReset;
  }

  get loginAttempt() {
    return this.prisma.loginAttempt;
  }

  get staffPermission() {
    return this.prisma.staffPermission;
  }

  get auditLog() {
    return this.prisma.auditLog;
  }

  get rateLimit() {
    return this.prisma.rateLimit;
  }

  get securityEvent() {
    return this.prisma.securityEvent;
  }
get merchantVerification() {
    return this.prisma.merchantVerification;
  }
  
  get merchantLimits() {
    return this.prisma.merchantLimits;
  }

  $transaction(p: any) {
    return this.prisma.$transaction(p);
  }
}