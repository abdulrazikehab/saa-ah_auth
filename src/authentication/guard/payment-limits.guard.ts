// apps/app-auth/src/auth/guards/payment-limits.guard.ts
import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { KycService } from '../kyc/kyc.service';

@Injectable()
export class PaymentLimitsGuard implements CanActivate {
  constructor(private kycService: KycService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    const amount = request.body.amount || request.query.amount;

    if (!amount) {
      return true; // No amount to check
    }

    const limitCheck = await this.kycService.checkPaymentLimit(user.tenantId, parseFloat(amount));
    
    if (!limitCheck.allowed) {
      throw new ForbiddenException(limitCheck.reason);
    }

    return true;
  }
}