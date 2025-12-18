import { 
  Controller,
  Get,
  UseGuards,
  Request,
  UnauthorizedException,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../guard/jwt-auth.guard';
import { AuthService } from './auth.service';

/**
 * Merchant auth endpoints that share the same auth service as regular users.
 * This allows merchant apps (or tools like Postman) to call /api/merchant/auth/me
 * on the auth service (port 3001) to get the current authenticated user.
 */
@Controller('api/merchant/auth')
export class MerchantAuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getMe(@Request() req: any) {
    const userId = req.user?.userId || req.user?.id;
    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }

    const user = await this.authService.getUserProfile(userId);

    return {
      user,
    };
  }
}


