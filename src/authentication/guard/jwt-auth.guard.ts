import { Injectable, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(JwtAuthGuard.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private reflector: Reflector,
  ) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    
    // Check for admin API key first (for admin panel access)
    const adminApiKey = request.headers['x-admin-api-key'];
    const expectedAdminKey = this.configService.get<string>('ADMIN_API_KEY') || 'Saeaa2025Admin!';

    if (adminApiKey && adminApiKey === expectedAdminKey) {
      // Admin API key is valid - set a system user
      request.user = {
        id: 'system-admin',
        tenantId: null,
        role: 'SUPER_ADMIN',
        email: 'system@admin.local'
      };
      // Bypass standard JWT check
      return true;
    }
    
    // Otherwise, proceed with standard JWT verification
    try {
      return super.canActivate(context);
    } catch (error) {
      this.logger.error('JWT authentication failed:', error);
      throw new UnauthorizedException('Authentication failed');
    }
  }

  handleRequest(err: any, user: any, info: any) {
    if (err || !user) {
      this.logger.error('JWT validation error:', { err, info, hasUser: !!user });
      throw err || new UnauthorizedException('Invalid or expired token');
    }
    return user;
  }
}