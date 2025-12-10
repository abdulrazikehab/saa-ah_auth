// apps/app-auth/src/database/database.service.ts
import { Injectable, OnModuleInit } from '@nestjs/common';

@Injectable()
export class DatabaseService implements OnModuleInit {
  private prisma: any;

  constructor() {
    const { PrismaClient } = require('.prisma/client');
    this.prisma = new PrismaClient();
  }

  async onModuleInit() {
    await this.prisma.$connect();
  }

  get user() {
    return this.prisma.user;
  }

  get tenant() {
    return this.prisma.tenant;
  }

  get refreshToken() {
    return this.prisma.refreshToken;
  }

  $transaction(p: any) {
    return this.prisma.$transaction(p);
  }
}