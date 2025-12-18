import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { AppModule } from './app.module';
import * as dotenv from 'dotenv';
import * as path from 'path';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { Request, Response, NextFunction } from 'express';

// Load environment variables FIRST
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  
  try {
    const app = await NestFactory.create(AppModule);
    
    // CRITICAL: Enable CORS FIRST before any other middleware to prevent duplicate headers
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

    // CRITICAL: Handle OPTIONS preflight requests FIRST before CORS middleware
    // This ensures preflight requests get proper CORS headers
    app.use((req: Request, res: Response, next: NextFunction) => {
      if (req.method === 'OPTIONS') {
        // Set CORS headers for preflight
        const origin = req.headers.origin;
        if (origin) {
          res.setHeader('Access-Control-Allow-Origin', origin);
        } else {
          res.setHeader('Access-Control-Allow-Origin', '*');
        }
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD');
        res.setHeader('Access-Control-Allow-Headers', [
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
        ].join(', '));
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours
        return res.status(204).end(); // Respond to preflight immediately
      }
      next();
    });

    // CRITICAL: Enable CORS FIRST before any other middleware
    // Use Express CORS directly to set headers properly
    app.use(cors({
      origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean | string) => void) => {
        // Always allow the origin if present, or allow all if no origin
        callback(null, origin || true);
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
    }));

    // CRITICAL: Remove duplicate CORS headers before response is sent
    // This prevents duplicates from proxy/nginx/vercel
    app.use((req: Request, res: Response, next: NextFunction) => {
      const originalEnd = res.end.bind(res);
      res.end = function(chunk?: any, encoding?: any, cb?: any) {
        // Remove duplicate Access-Control-Allow-Origin headers
        const headers = res.getHeaders();
        const originHeader = headers['access-control-allow-origin'] || headers['Access-Control-Allow-Origin'];
        if (originHeader && Array.isArray(originHeader)) {
          // Multiple values found, keep only the first one
          res.removeHeader('Access-Control-Allow-Origin');
          res.removeHeader('access-control-allow-origin');
          res.setHeader('Access-Control-Allow-Origin', originHeader[0]);
        } else if (originHeader && typeof originHeader === 'string' && originHeader.includes(',')) {
          // Single string with comma-separated values, keep only first
          const firstValue = originHeader.split(',')[0].trim();
          res.removeHeader('Access-Control-Allow-Origin');
          res.removeHeader('access-control-allow-origin');
          res.setHeader('Access-Control-Allow-Origin', firstValue);
        }
        return originalEnd(chunk, encoding, cb);
      };
      next();
    });
    
    // Enable cookie parser AFTER CORS
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
    
    const port = process.env.CORE_PORT || 3001;
    await app.listen(port,'0.0.0.0');
    logger.log(`✅ Auth service running on port ${port}`);
  } catch (error) {
    logger.error('Failed to start auth service:', error);
    process.exit(1);
  }
}
bootstrap();