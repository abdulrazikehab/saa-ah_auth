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
        if (!origin) {
          logger.debug('✅ CORS: Allowing request with no origin');
          return callback(null, true);
        }
        
        logger.debug(`🔍 CORS: Checking origin: ${origin}`);
        
        // List of allowed origins
        const allowedOrigins = [
          'http://localhost:4173',
          'http://localhost:3000',
          'http://localhost:8080',
          'http://127.0.0.1:4173',
          'http://127.0.0.1:3000',
          'http://127.0.0.1:8080',
          'https://saeaa.com',
          'https://saeaa.net',
          'http://saeaa.com',
          'http://saeaa.net',
          'https://www.saeaa.com',
          'https://www.saeaa.net',
          'https://app.saeaa.com',
          'https://app.saeaa.net',
          process.env.FRONTEND_URL,
        ].filter(Boolean);
        
        // Check if origin is in allowed list
        if (allowedOrigins.includes(origin)) {
          logger.log(`✅ CORS: Allowed origin (whitelist): ${origin}`);
          return callback(null, origin); // Return the origin string to avoid duplicates
        }
        
        // Allow any subdomain of localhost (e.g., mystore.localhost:8080)
        if (origin.match(/^http:\/\/[\w-]+\.localhost(:\d+)?$/)) {
          logger.log(`✅ CORS: Allowed origin (localhost subdomain): ${origin}`);
          return callback(null, origin);
        }
        
        // Allow main production domains (including www and app subdomains)
        if (origin.match(/^https?:\/\/(www\.|app\.)?(saeaa\.com|saeaa\.net)(:\d+)?$/)) {
          logger.log(`✅ CORS: Allowed origin (production domain): ${origin}`);
          return callback(null, origin);
        }
        
        // Allow any subdomain of saeaa.com (e.g., store.saeaa.com)
        if (origin.match(/^https?:\/\/[\w-]+\.saeaa\.com$/)) {
          logger.log(`✅ CORS: Allowed origin (saeaa.com subdomain): ${origin}`);
          return callback(null, origin);
        }
        
        // Allow any subdomain of saeaa.net (e.g., store.saeaa.net)
        if (origin.match(/^https?:\/\/[\w-]+\.saeaa\.net$/)) {
          logger.log(`✅ CORS: Allowed origin (saeaa.net subdomain): ${origin}`);
          return callback(null, origin);
        }
        
        // Legacy: Allow any subdomain of saa'ah.com (if still in use)
        if (origin.match(/^https?:\/\/[\w-]+\.saa'ah\.com$/)) {
          logger.log(`✅ CORS: Allowed origin (legacy domain): ${origin}`);
          return callback(null, origin);
        }
        
        // Allow local network IPs
        if (origin.match(/^http:\/\/192\.168\.\d+\.\d+(:\d+)?$/)) {
          logger.log(`✅ CORS: Allowed origin (local network): ${origin}`);
          return callback(null, origin);
        }
        
        logger.warn(`❌ CORS: Blocked origin: ${origin}`);
        callback(new Error('Not allowed by CORS'));
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'Accept',
        'Origin',
        'Access-Control-Allow-Headers',
        'Access-Control-Request-Method',
        'Access-Control-Request-Headers',
        'Access-Control-Allow-Origin',
        'Access-Control-Allow-Credentials',
        'X-Tenant-Id',
        'x-tenant-id',
        'X-Tenant-Domain',
        'x-tenant-domain',
        'X-Session-ID',
        'x-session-id',
        'X-Admin-API-Key',
        'x-admin-api-key',
        'X-API-Key',
        'x-api-key',
        'X-ApiKey',
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