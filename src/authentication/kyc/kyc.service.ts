// src/auth/kyc/kyc.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

export enum KycStatus {
  PENDING = 'PENDING',
  UNDER_REVIEW = 'UNDER_REVIEW',
  VERIFIED = 'VERIFIED',
  REJECTED = 'REJECTED'
}

export enum DocumentType {
  NATIONAL_ID = 'NATIONAL_ID',
  PASSPORT = 'PASSPORT',
  DRIVING_LICENSE = 'DRIVING_LICENSE',
  BUSINESS_LICENSE = 'BUSINESS_LICENSE'
}

@Injectable()
export class KycService {
  private readonly logger = new Logger(KycService.name);

  constructor(private prisma: PrismaService) {}

  async submitKycApplication(tenantId: string, kycData: {
    documentType: DocumentType;
    documentNumber: string;
    documentFront: string;
    documentBack?: string;
    businessName?: string;
    taxNumber?: string;
  }) {
    return this.prisma.merchantVerification.create({
      data: {
        tenantId,
        status: KycStatus.PENDING,
        ...kycData,
        submittedAt: new Date(),
      },
    });
  }

  async getKycStatus(tenantId: string) {
    return this.prisma.merchantVerification.findFirst({
      where: { tenantId },
      orderBy: { submittedAt: 'desc' },
    });
  }

  async updateMerchantLimits(tenantId: string, limitsData: {
    maxSinglePayment?: number;
    maxDailyVolume?: number;
    maxMonthlyVolume?: number;
    allowedPaymentMethods?: string[];
  }) {
    const jsonPaymentMethods = limitsData.allowedPaymentMethods 
      ? JSON.stringify(limitsData.allowedPaymentMethods)
      : undefined;

    return this.prisma.merchantLimits.upsert({
      where: { tenantId },
      create: {
        tenantId,
        maxSinglePayment: limitsData.maxSinglePayment || 5000,
        maxDailyVolume: limitsData.maxDailyVolume || 20000,
        maxMonthlyVolume: limitsData.maxMonthlyVolume || 100000,
        allowedPaymentMethods: jsonPaymentMethods || JSON.stringify(['MADA', 'VISA', 'MASTERCARD']),
      },
      update: {
        ...(limitsData.maxSinglePayment && { maxSinglePayment: limitsData.maxSinglePayment }),
        ...(limitsData.maxDailyVolume && { maxDailyVolume: limitsData.maxDailyVolume }),
        ...(limitsData.maxMonthlyVolume && { maxMonthlyVolume: limitsData.maxMonthlyVolume }),
        ...(jsonPaymentMethods && { allowedPaymentMethods: jsonPaymentMethods }),
      },
    });
  }

  async updateKycStatus(verificationId: string, status: KycStatus, reviewedBy: string, notes?: string) {
    return this.prisma.merchantVerification.update({
      where: { id: verificationId },
      data: {
        status,
        reviewedBy,
        reviewedAt: new Date(),
        reviewNotes: notes,
      },
    });
  }

  async getPaymentLimits(tenantId: string) {
    const limits = await this.prisma.merchantLimits.findUnique({
      where: { tenantId },
    });

    const kyc = await this.getKycStatus(tenantId);
    const isVerified = kyc?.status === KycStatus.VERIFIED;

    // Parse JSON back to array
    const allowedMethods = limits?.allowedPaymentMethods 
      ? JSON.parse(limits.allowedPaymentMethods as string)
      : ['MADA', 'VISA', 'MASTERCARD'];

    return {
      maxSinglePayment: limits?.maxSinglePayment || (isVerified ? 50000 : 5000),
      maxDailyVolume: limits?.maxDailyVolume || (isVerified ? 200000 : 20000),
      maxMonthlyVolume: limits?.maxMonthlyVolume || (isVerified ? 1000000 : 100000),
      allowedPaymentMethods: isVerified 
        ? ['MADA', 'VISA', 'MASTERCARD', 'APPLE_PAY'] 
        : allowedMethods,
      kycRequired: !isVerified,
      currentKycStatus: kyc?.status || KycStatus.PENDING,
    };
  }

  async checkPaymentLimit(tenantId: string, amount: number): Promise<{ allowed: boolean; reason?: string }> {
    const limits = await this.getPaymentLimits(tenantId);
    
    if (amount > limits.maxSinglePayment) {
      return {
        allowed: false,
        reason: `Single payment exceeds limit of ${limits.maxSinglePayment}. KYC verification required.`
      };
    }

    // Check daily volume (you'd implement this with actual transaction data)
    const todayVolume = await this.getTodayTransactionVolume(tenantId);
    if (todayVolume + amount > limits.maxDailyVolume) {
      return {
        allowed: false,
        reason: `Daily volume limit exceeded. KYC verification required.`
      };
    }

    return { allowed: true };
  }

  private async getTodayTransactionVolume(tenantId: string): Promise<number> {
    // Implement with your transaction service
    return 0;
  }

  async approveKycManually(tenantId: string, adminId: string) {
    // 1. Check if verification record exists
    const existingVerification = await this.prisma.merchantVerification.findFirst({
      where: { tenantId },
    });

    let verification;

    if (existingVerification) {
      // Update existing
      verification = await this.prisma.merchantVerification.update({
        where: { id: existingVerification.id },
        data: {
          status: KycStatus.VERIFIED,
          reviewedBy: adminId,
          reviewedAt: new Date(),
          reviewNotes: 'Manually approved by admin via API',
        },
      });
    } else {
      // Create new verified record
      verification = await this.prisma.merchantVerification.create({
        data: {
          tenantId,
          status: KycStatus.VERIFIED,
          documentType: DocumentType.BUSINESS_LICENSE, // Default placeholder
          documentNumber: 'MANUAL_APPROVAL',
          documentFront: 'MANUAL_APPROVAL',
          reviewedBy: adminId,
          reviewedAt: new Date(),
          reviewNotes: 'Manually approved by admin via API',
          submittedAt: new Date(),
        },
      });
    }

    // 2. Unlock limits
    await this.updateMerchantLimits(tenantId, {
      maxSinglePayment: 50000,
      maxDailyVolume: 200000,
      maxMonthlyVolume: 1000000,
      allowedPaymentMethods: ['MADA', 'VISA', 'MASTERCARD', 'APPLE_PAY'],
    });

    return {
      message: 'KYC manually approved and limits unlocked',
      verification,
    };
  }
}