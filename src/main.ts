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
    
    // Enable CORS with proper origin handling to prevent duplicate headers
    // app.enableCors({
    //   origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean | string) => void) => {
    //     // Allow requests with no origin (like mobile apps or curl requests)
    //     if (!origin) {
    //       return callback(null, true);
    //     }
        
    //     // List of allowed origins
    //     const allowedOrigins = [
    //       'http://localhost:4173',
    //       'http://localhost:3000',
    //       'http://localhost:8080',
    //       'http://127.0.0.1:4173',
    //       'http://127.0.0.1:3000',
    //       'http://127.0.0.1:8080',
    //       'https://saeaa.com',
    //       'https://saeaa.net',
    //       'http://saeaa.com',
    //       'http://saeaa.net',
    //       'https://www.saeaa.com',
    //       'https://www.saeaa.net',
    //       'https://app.saeaa.com',
    //       'https://app.saeaa.net',
    //       process.env.FRONTEND_URL,
    //     ].filter(Boolean);
        
    //     // Check if origin is in allowed list
    //     if (allowedOrigins.includes(origin)) {
    //       return callback(null, origin); // Return origin string to prevent duplicates
    //     }
        
    //     // Allow any subdomain of saeaa.com or saeaa.net
    //     if (origin.match(/^https?:\/\/([\w-]+\.)?(saeaa\.com|saeaa\.net)(:\d+)?$/)) {
    //       return callback(null, origin);
    //     }
        
    //     // Allow localhost subdomains
    //     if (origin.match(/^http:\/\/[\w-]+\.localhost(:\d+)?$/)) {
    //       return callback(null, origin);
    //     }
        
    //     // Allow local network IPs
    //     if (origin.match(/^http:\/\/192\.168\.\d+\.\d+(:\d+)?$/)) {
    //       return callback(null, origin);
    //     }
        
    //     // Reject other origins
    //     callback(new Error('Not allowed by CORS'));
    //   },
    //   credentials: true,
    //   methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    //   allowedHeaders: [
    //     'Content-Type',
    //     'Authorization',
    //     'X-Requested-With',
    //     'Accept',
    //     'Origin',
    //     'X-Tenant-Id',
    //     'X-Tenant-Domain',
    //     'x-tenant-id',
    //     'x-tenant-domain',
    //     'X-Session-ID',
    //     'x-session-id',
    //     'X-Admin-API-Key',
    //     'x-admin-api-key',
    //     'X-API-Key',
    //     'X-ApiKey',
    //     'x-api-key',
    //     'x-apikey'
    //   ],
    //   exposedHeaders: [
    //     'Content-Type',
    //     'Authorization'
    //   ],
    //   preflightContinue: false,
    //   optionsSuccessStatus: 204,
    // });

    // Enable CORS - allow all origins but prevent duplicate headers
    app.enableCors({
      origin: (origin, callback) => {
        // Allow all origins - always return the origin string when present to prevent duplicates
        // When origin is undefined (no-origin requests), return true
        if (origin) {
          callback(null, origin); // Return origin string explicitly
        } else {
          callback(null, true); // Allow requests with no origin
        }
      },
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
        'Authorization'
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