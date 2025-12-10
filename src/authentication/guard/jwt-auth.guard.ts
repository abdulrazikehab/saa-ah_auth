import { Injectable, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtAuthGuard {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    
    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    try {
      const secret = this.configService.get<string>('JWT_SECRET');
      if (!secret) {
        console.error('❌ JWT_SECRET is not configured in environment variables');
        throw new UnauthorizedException('Server configuration error');
      }

      const payload = this.jwtService.verify(token, { secret });
      
      // Verify required payload fields
      if (!payload.sub) {
        console.error('❌ Invalid token payload - missing sub');
        throw new UnauthorizedException('Invalid token payload');
      }

      request.user = {
        id: payload.sub,
        tenantId: payload.tenantId || null,
        role: payload.role,
        email: payload.email
      };
      request.tenantId = payload.tenantId || null;
      
      return true;
    } catch (error) {
      console.error('❌ JWT verification failed:', error);
      throw new UnauthorizedException(error);
    }
  }

  private extractTokenFromHeader(request: any): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}