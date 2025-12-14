import { Controller, Get } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';

@Controller()
export class AppController {
  @Get()
  @SkipThrottle()
  getHealth() {
    return {
      success: true,
      service: 'app-auth',
      status: 'running',
      timestamp: new Date().toISOString(),
    };
  }
}

