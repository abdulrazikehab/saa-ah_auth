// src/auth/kyc/kyc.module.ts
import { Module } from '@nestjs/common';
import { KycService } from './kyc.service';
import { KycController } from './kyc.controller';

@Module({
  providers: [KycService],
  controllers: [KycController],
  exports: [KycService],
})
export class KycModule {}