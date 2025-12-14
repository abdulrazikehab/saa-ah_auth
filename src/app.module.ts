// src/app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD, APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { AuthModule } from './authentication/auth/auth.module';
import { StaffModule } from './staff/staff.module';
import { PrismaModule } from './prisma/prisma.module';
import { EmailModule } from './email/email.module';
import { RateLimitingModule } from './rate-limiting/rate-limiting.module';
import { AdminController } from './admin/admin.controller';
import { AppController } from './app.controller';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import { ActionLoggingInterceptor } from './common/interceptors/action-logging.interceptor';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    // Global Throttler configuration
    ThrottlerModule.forRootAsync({
      useFactory: () => [
        {
          ttl: 60000, // 1 minute
          limit: 100, // 100 requests per minute
        },
      ],
    }),
    AuthModule,
    StaffModule,
    PrismaModule,
    EmailModule,
    RateLimitingModule,
  ],
  controllers: [AppController, AdminController],
  providers: [
    // Apply ThrottlerGuard globally
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    // Apply exception filter globally
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter,
    },
    // Apply action logging interceptor globally
    {
      provide: APP_INTERCEPTOR,
      useClass: ActionLoggingInterceptor,
    },
  ],
})
export class AppModule {}