import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import * as dotenv from 'dotenv';
import * as path from 'path';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';

// Load environment variables FIRST
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

async function bootstrap() {
  // Verify JWT_SECRET is loaded before starting
  if (!process.env.JWT_SECRET) {
    console.error('❌ JWT_SECRET is not configured in auth service environment variables');
    process.exit(1);
  }

  console.log('✅ Auth Service JWT_SECRET:', process.env.JWT_SECRET ? 'Loaded' : 'Missing');
  
  const app = await NestFactory.create(AppModule);
  
  // Enable global validation
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }));

  // Apply global exception filter
  app.useGlobalFilters(new AllExceptionsFilter());
  
  // Enable CORS for Postman testing
  app.enableCors();
  
  await app.listen(3001);
  console.log('✅ Auth service running on http://localhost:3001');
  console.log('✅ JWT_SECRET is configured');
}
bootstrap();