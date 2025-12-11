import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class ActionLoggingInterceptor implements NestInterceptor {
  constructor(private prisma: PrismaService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url, body, query, params } = request;
    const user = (request as any).user;
    const ipAddress = request.ip || request.connection?.remoteAddress;
    const userAgent = request.headers['user-agent'];

    // Skip logging for certain endpoints
    const skipPaths = ['/auth/health', '/auth/security-events', '/auth/audit-logs', '/auth/error-logs'];
    if (skipPaths.some(path => url.includes(path))) {
      return next.handle();
    }

    return next.handle().pipe(
      tap(async (response) => {
        try {
          // Log all successful actions
          // If response exists and is not an error, it's a successful request
          const isSuccess = response && (
            (typeof response === 'object' && !('error' in response) && !('statusCode' in response && response.statusCode >= 400)) ||
            (typeof response === 'object' && 'statusCode' in response && response.statusCode >= 200 && response.statusCode < 300)
          );

          if (isSuccess) {
            await this.prisma.auditLog.create({
              data: {
                userId: user?.id || user?.sub || undefined,
                tenantId: user?.tenantId || request.headers['x-tenant-id'] as string || undefined,
                action: `${method} ${url.split('?')[0]}`,
                resourceType: this.getResourceType(url),
                resourceId: params?.id || query?.id || body?.id || undefined,
                oldValues: null,
                newValues: JSON.stringify({ body, query, params }),
                ipAddress,
                userAgent,
                metadata: JSON.stringify({
                  method,
                  url,
                  responseType: typeof response,
                  userEmail: user?.email,
                  userName: user?.name,
                }),
              },
            });
          }
        } catch (error) {
          // Silent fail - don't break request if logging fails
        }
      }),
    );
  }

  private getResourceType(url: string): string {
    if (url.includes('/auth/login')) return 'AUTH';
    if (url.includes('/auth/signup')) return 'AUTH';
    if (url.includes('/auth/refresh')) return 'AUTH';
    if (url.includes('/auth/logout')) return 'AUTH';
    if (url.includes('/auth/password')) return 'AUTH';
    if (url.includes('/staff')) return 'STAFF';
    return 'SYSTEM';
  }
}

