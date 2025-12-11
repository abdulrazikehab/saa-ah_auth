import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
  Injectable,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  constructor(private prisma: PrismaService) {}

  async catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message: string | object = 'Internal server error';
    let stack: string | undefined;

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse();
      message = typeof exceptionResponse === 'string' 
        ? exceptionResponse 
        : exceptionResponse;
    } else if (exception instanceof Error) {
      message = exception.message;
      stack = exception.stack;
    }

    // Save error to database
    try {
      const user = (request as any).user;
      await this.prisma.auditLog.create({
        data: {
          userId: user?.id || user?.sub || undefined,
          tenantId: user?.tenantId || request.headers['x-tenant-id'] as string || undefined,
          action: 'ERROR',
          resourceType: 'SYSTEM',
          resourceId: status.toString(),
          oldValues: null,
          newValues: null,
          ipAddress: request.ip || request.connection?.remoteAddress || undefined,
          userAgent: request.headers['user-agent'] || undefined,
          metadata: JSON.stringify({
            severity: status >= 500 ? 'CRITICAL' : status >= 400 ? 'HIGH' : 'MEDIUM',
            message: typeof message === 'string' ? message : JSON.stringify(message),
            stack,
            method: request.method,
            path: request.url,
            statusCode: status,
          }),
        },
      });
    } catch (error) {
      // Silent fail - don't break error response if logging fails
    }

    // Send standardized error response
    response.status(status).json({
      success: false,
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      message,
    });
  }
}
