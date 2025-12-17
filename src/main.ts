import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { AppModule } from './app.module';
import * as dotenv from 'dotenv';
import * as path from 'path';
import cookieParser from 'cookie-parser';

// Load environment variables FIRST
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  
  try {
    const app = await NestFactory.create(AppModule);
    
    // Enable cookie parser
    app.use(cookieParser());
    
    // Verify JWT_SECRET is loaded before starting
    if (!process.env.JWT_SECRET) {
      logger.error('❌ JWT_SECRET is not configured in auth service environment variables');
      process.exit(1);
    }
    
    // Enable global validation
    app.useGlobalPipes(new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }));

    // Exception filter is now registered in app.module.ts via APP_FILTER
    
    // Enable CORS - Allow all origins
    app.enableCors({
      origin: true, // Allow all origins
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'Accept',
        'Origin',
        'X-Tenant-Id',
        'X-Tenant-Domain',
        'x-tenant-id',
        'x-tenant-domain',
        'X-Session-ID',
        'x-session-id',
        'X-Admin-API-Key',
        'x-admin-api-key',
        'X-API-Key',
        'X-ApiKey',
        'x-api-key',
        'x-apikey'
      ],
      exposedHeaders: [
        'Content-Type',
        'Authorization',
        'Access-Control-Allow-Origin',
        'Access-Control-Allow-Credentials'
      ],
      preflightContinue: false,
      optionsSuccessStatus: 204,
    });
    
    const port = process.env.CORE_PORT || 3001;
    await app.listen(port,'0.0.0.0');
    logger.log(`✅ Auth service running on port ${port}`);
  } catch (error) {
    logger.error('Failed to start auth service:', error);
    process.exit(1);
  }
}
bootstrap();