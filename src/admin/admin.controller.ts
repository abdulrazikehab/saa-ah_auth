import { Controller, Post, Delete, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { RateLimitingService } from '../rate-limiting/rate-limiting.service';

@Controller('admin')
export class AdminController {
  constructor(private rateLimitingService: RateLimitingService) {}

  @Post('block-ip')
  @HttpCode(HttpStatus.OK)
  async blockIp(@Body() body: { ip: string }) {
    await this.rateLimitingService.blockIp(body.ip);
    return { message: `IP ${body.ip} has been blocked` };
  }

  @Delete('clear-rate-limits')
  @HttpCode(HttpStatus.OK)
  async clearRateLimits() {
    await this.rateLimitingService.clearAllRateLimits();
    return { message: 'All rate limits cleared successfully' };
  }
}
