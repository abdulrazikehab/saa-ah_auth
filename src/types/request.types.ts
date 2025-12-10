import { Request } from 'express';

export interface AuthenticatedRequest extends Request {
  user: {
    id(tenantId: string, userId: string, id: any): unknown;
    sub: string;
    email: string;
    role: string;
    tenantId: string;
  };
  tenantId: string;
}