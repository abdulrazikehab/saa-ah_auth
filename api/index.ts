import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { AppModule } from '../src/app.module';
import * as dotenv from 'dotenv';
import * as path from 'path';
import cookieParser from 'cookie-parser';
import { ExpressAdapter } from '@nestjs/platform-express';
import express from 'express';

// Load environment variables FIRST
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

let cachedApp: any = null;

async function createApp() {
  if (cachedApp) {
    return cachedApp;
  }

  const logger = new Logger('Bootstrap');
  
  try {
    // Check required environment variables
    const requiredEnvVars = ['JWT_SECRET', 'DATABASE_URL'];
    const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
    
    if (missingVars.length > 0) {
      logger.error(`❌ Missing required environment variables: ${missingVars.join(', ')}`);
      throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
    }
    
    const expressApp = express();
    const app = await NestFactory.create(
      AppModule,
      new ExpressAdapter(expressApp),
    );
    
    // Enable cookie parser
    app.use(cookieParser());
    
    // Enable global validation
    app.useGlobalPipes(new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }));

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
          'https://auth-test-tau-hazel.vercel.app',
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
        
        // Allow Vercel preview deployments
        if (origin.match(/^https:\/\/.*\.vercel\.app$/)) {
          return callback(null, true);
        }
        
        callback(new Error('Not allowed by CORS'));
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'X-Tenant-Id', 'X-Tenant-Domain', 'X-Session-ID', 'X-Admin-API-Key'],
    });
    
    await app.init();
    cachedApp = expressApp;
    logger.log('✅ Auth service initialized for Vercel');
    return expressApp;
  } catch (error: any) {
    logger.error('Failed to initialize auth service:', error);
    logger.error('Error stack:', error?.stack);
    logger.error('Error details:', JSON.stringify(error, Object.getOwnPropertyNames(error)));
    throw error;
  }
}

export default async function handler(req: express.Request, res: express.Response) {
  try {
    const app = await createApp();
    return app(req, res);
  } catch (error: any) {
    console.error('Error handling request:', error);
    console.error('Error stack:', error?.stack);
    console.error('Error details:', JSON.stringify(error, Object.getOwnPropertyNames(error)));
    
    // Ensure response hasn't been sent
    if (!res.headersSent) {
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? error?.message : undefined,
        stack: process.env.NODE_ENV === 'development' ? error?.stack : undefined,
      });
    }
  }
}

