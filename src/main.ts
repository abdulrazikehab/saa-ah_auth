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
    
    // Enable CORS with credentials for cookies
    app.enableCors({
      origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        // List of allowed origins
        const allowedOrigins = [
          'http://localhost:4173',
          'http://localhost:3000',
          'http://localhost:8080',
          'http://127.0.0.1:4173',
          'http://127.0.0.1:3000',
          'http://127.0.0.1:8080',
          process.env.FRONTEND_URL,
        ].filter(Boolean);
        
        // Check if origin is in allowed list
        if (allowedOrigins.includes(origin)) {
          return callback(null, true);
        }
        
        // Allow any subdomain of localhost (e.g., mystore.localhost:8080)
        if (origin.match(/^http:\/\/[\w-]+\.localhost(:\d+)?$/)) {
          return callback(null, true);
        }
        
        // Allow any subdomain of saa'ah.com
        if (origin.match(/^https?:\/\/[\w-]+\.saa'ah\.com$/)) {
          return callback(null, true);
        }
        
        // Allow local network IPs
        if (origin.match(/^http:\/\/192\.168\.\d+\.\d+(:\d+)?$/)) {
          return callback(null, true);
        }
        
        callback(new Error('Not allowed by CORS'));
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'X-Tenant-Id', 'X-Tenant-Domain', 'X-Session-ID', 'X-Admin-API-Key'],
    });
    
    await app.listen(3001);
    logger.log('✅ Auth service running on http://localhost:3001');
  } catch (error) {
    logger.error('Failed to start auth service:', error);
    process.exit(1);
  }
}
bootstrap();