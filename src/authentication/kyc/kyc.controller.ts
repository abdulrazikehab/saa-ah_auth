import { Controller, Post, Get, Body, UseGuards, Request, Put, Param } from '@nestjs/common';
import { JwtAuthGuard } from '../../authentication/guard/jwt-auth.guard';
import { KycService, KycStatus } from './kyc.service';

@Controller('auth/kyc')
@UseGuards(JwtAuthGuard)
export class KycController {
  constructor(private kycService: KycService) {}

  @Post('submit')
  async submitKyc(@Request() req: any, @Body() kycData: any) {
    return this.kycService.submitKycApplication(req.user.tenantId, kycData);
  }

  @Get('status')
  async getKycStatus(@Request() req: any) {
    return this.kycService.getKycStatus(req.user.tenantId);
  }

  @Get('payment-limits')
  async getPaymentLimits(@Request() req: any) {
    return this.kycService.getPaymentLimits(req.user.tenantId);
  }

  // Admin endpoints
  @Put(':verificationId/status')
  async updateKycStatus(
    @Param('verificationId') verificationId: string,
    @Body() updateData: { status: KycStatus; notes?: string },
    @Request() req: any
  ) {
    return this.kycService.updateKycStatus(
      verificationId, 
      updateData.status, 
      req.user.id, 
      updateData.notes
    );
  }

  @Post('admin/approve-instant')
  async approveKycInstant(
    @Request() req: any,
    @Body() body: { tenantId: string }
  ) {
    // In a real app, add a Guard here to check for SUPER_ADMIN role
    return this.kycService.approveKycManually(body.tenantId, req.user.id);
  }
}