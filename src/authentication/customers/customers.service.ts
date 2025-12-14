// src/customers/customers.service.ts
import { Injectable, Logger, NotFoundException, ConflictException, UnauthorizedException, BadRequestException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { validateEmailWithMx, generateRecoveryId } from '../../utils/email-validator';
import { checkIpReputation } from '../../utils/ip-checker';

export interface CreateCustomerDto {
  email: string;
  phone?: string;
  firstName?: string;
  lastName?: string;
  metadata?: unknown;
}

export interface UpdateCustomerDto {
  phone?: string;
  firstName?: string;
  lastName?: string;
  metadata?: unknown;
}

@Injectable()
export class CustomersService {
  private readonly logger = new Logger(CustomersService.name);

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  /**
   * Customer signup for storefront users
   */
  async customerSignup(tenantId: string, signupDto: { email: string; password: string; firstName?: string; lastName?: string; phone?: string }, ipAddress?: string) {
    this.logger.log(`Customer signup attempt for tenant: ${tenantId}, email: ${signupDto.email}, IP: ${ipAddress}`);

    // Check IP for VPN/Proxy
    if (ipAddress) {
      const ipCheck = await checkIpReputation(ipAddress);
      if (ipCheck.isVpn || ipCheck.isProxy || ipCheck.isTor) {
        this.logger.warn(`🔴 Blocking customer signup - VPN/Proxy detected: ${signupDto.email}, IP: ${ipAddress}, ISP: ${ipCheck.isp}`);
        throw new ForbiddenException('VPN/Proxy usage is not allowed. Please disable your VPN and try again.');
      }
    }


    // Validate email - check for fake/disposable emails
    const emailValidation = await validateEmailWithMx(signupDto.email);
    if (!emailValidation.isValid) {
      this.logger.warn(`Customer signup with invalid email: ${signupDto.email} - ${emailValidation.reason}`);
      throw new BadRequestException(emailValidation.reason || 'Invalid email address');
    }

    // For customer signups, we need a valid tenant context
    // Try to find by ID first, then by subdomain, then create if needed
    let tenant = await this.prisma.tenant.findUnique({
      where: { id: tenantId },
    });
    
    // If not found by ID, try subdomain (common for 'default' tenant)
    if (!tenant) {
      const subdomain = tenantId === 'default' ? 'default' : `store-${tenantId.substring(0, 8)}`;
      tenant = await this.prisma.tenant.findUnique({
        where: { subdomain },
      });
    }
    
    // If still not found, create the tenant
    if (!tenant) {
      this.logger.log(`Tenant '${tenantId}' not found, creating for customer signup...`);
      try {
        const subdomain = tenantId === 'default' ? 'default' : `store-${tenantId.substring(0, 8)}`;
        tenant = await this.prisma.tenant.create({
          data: {
            id: tenantId,
            name: tenantId === 'default' ? 'Default Store' : `Store-${tenantId.substring(0, 8)}`,
            subdomain,
            plan: 'STARTER',
            status: 'ACTIVE',
          },
        });
        this.logger.log(`✅ Tenant '${tenantId}' created successfully for customer signup`);
      } catch (error: any) {
        // Handle unique constraint violations - tenant might exist with different ID
        if (error?.code === 'P2002') {
          this.logger.log(`Tenant constraint conflict, finding existing tenant...`);
          // Try to find by subdomain again in case of race condition
          const subdomain = tenantId === 'default' ? 'default' : `store-${tenantId.substring(0, 8)}`;
          tenant = await this.prisma.tenant.findUnique({
            where: { subdomain },
          });
        }
        if (!tenant) {
          this.logger.error(`Failed to create or find tenant '${tenantId}': ${error?.message}`);
          throw new NotFoundException(`Store not found. Please check the store URL.`);
        }
      }
    }
    
    this.logger.log(`✅ Using tenant '${tenant.id}' (subdomain: ${tenant.subdomain}) for customer signup`);

    // Use the actual tenant ID from the found/created tenant
    const actualTenantId = tenant.id;

    // Check if customer already exists for this tenant
    const existingCustomer = await this.prisma.customer.findUnique({
      where: {
        tenantId_email: {
          tenantId: actualTenantId,
          email: signupDto.email,
        },
      },
    });

    if (existingCustomer) {
      throw new ConflictException('Customer with this email already exists');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(signupDto.password, 12);

    // Generate recovery ID
    const recoveryId = generateRecoveryId();

    // Create customer with password in metadata
    const customer = await this.prisma.customer.create({
      data: {
        tenantId: actualTenantId,
        email: signupDto.email,
        phone: signupDto.phone,
        firstName: signupDto.firstName,
        lastName: signupDto.lastName,
        recoveryId,
        metadata: JSON.stringify({ password: hashedPassword }),
      },
    });

    // Generate JWT token
    const token = this.jwtService.sign({
      sub: customer.id,
      email: customer.email,
      tenantId: customer.tenantId,
      type: 'customer',
    });

    this.logger.log(`✅ Customer created: ${customer.id}`);

    return {
      token,
      customer: {
        id: customer.id,
        email: customer.email,
        firstName: customer.firstName,
        lastName: customer.lastName,
        phone: customer.phone,
      },
      recoveryId, // Return recovery ID
    };
  }

  /**
   * Customer login for storefront users
   */
  async customerLogin(tenantId: string, loginDto: { email: string; password: string }) {
    this.logger.log(`Customer login attempt for tenant: ${tenantId}, email: ${loginDto.email}`);

    // Find customer
    const customer = await this.prisma.customer.findUnique({
      where: {
        tenantId_email: {
          tenantId,
          email: loginDto.email,
        },
      },
    });

    if (!customer) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Get password from metadata
    let metadata: { password?: string } = {};
    try {
      metadata = typeof customer.metadata === 'string' ? JSON.parse(customer.metadata) : customer.metadata as { password?: string };
    } catch (error) {
      this.logger.error('Failed to parse customer metadata:', error);
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!metadata.password) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(loginDto.password, metadata.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate JWT token
    const token = this.jwtService.sign({
      sub: customer.id,
      email: customer.email,
      tenantId: customer.tenantId,
      type: 'customer',
    });

    this.logger.log(`✅ Customer logged in: ${customer.id}`);

    return {
      token,
      customer: {
        id: customer.id,
        email: customer.email,
        firstName: customer.firstName,
        lastName: customer.lastName,
        phone: customer.phone,
      },
    };
  }

  async createCustomer(tenantId: string, createCustomerDto: CreateCustomerDto) {
    this.logger.log(`Creating customer for tenant: ${tenantId}, email: ${createCustomerDto.email}`);

    // Check if customer already exists
    const existingCustomer = await this.prisma.customer.findUnique({
      where: {
        tenantId_email: {
          tenantId,
          email: createCustomerDto.email,
        },
      },
    });

    if (existingCustomer) {
      throw new ConflictException('Customer with this email already exists');
    }

    const customer = await this.prisma.customer.create({
      data: {
        tenantId,
        ...createCustomerDto,
      },
    });

    this.logger.log(`✅ Customer created: ${customer.id}`);
    return customer;
  }

  async getCustomerById(tenantId: string, customerId: string) {
    const customer = await this.prisma.customer.findFirst({
      where: {
        id: customerId,
        tenantId,
      },
    });

    if (!customer) {
      throw new NotFoundException('Customer not found');
    }

    return customer;
  }

  async getCustomerByEmail(tenantId: string, email: string) {
    const customer = await this.prisma.customer.findUnique({
      where: {
        tenantId_email: {
          tenantId,
          email,
        },
      },
    });

    if (!customer) {
      throw new NotFoundException('Customer not found');
    }

    return customer;
  }

  async updateCustomer(tenantId: string, customerId: string, updateCustomerDto: UpdateCustomerDto) {
    // Verify customer exists and belongs to tenant
    const existingCustomer = await this.prisma.customer.findFirst({
      where: {
        id: customerId,
        tenantId,
      },
    });

    if (!existingCustomer) {
      throw new NotFoundException('Customer not found');
    }

    const updatedCustomer = await this.prisma.customer.update({
      where: { id: customerId },
      data: updateCustomerDto,
    });

    this.logger.log(`✅ Customer updated: ${customerId}`);
    return updatedCustomer;
  }

  async getCustomers(tenantId: string, page: number = 1, limit: number = 50, search?: string) {
    const skip = (page - 1) * limit;

    const whereClause: { tenantId: string; OR?: unknown[] } = { tenantId };

    if (search) {
      whereClause.OR = [
        { email: { contains: search, mode: 'insensitive' } },
        { firstName: { contains: search, mode: 'insensitive' } },
        { lastName: { contains: search, mode: 'insensitive' } },
        { phone: { contains: search, mode: 'insensitive' } },
      ];
    }

    const [customers, total] = await Promise.all([
      this.prisma.customer.findMany({
        where: whereClause,
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          email: true,
          phone: true,
          firstName: true,
          lastName: true,
          createdAt: true,
          updatedAt: true,
          metadata: true,
        },
      }),
      this.prisma.customer.count({
        where: whereClause,
      }),
    ]);

    return {
      data: customers,
      meta: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        hasNextPage: page < Math.ceil(total / limit),
        hasPrevPage: page > 1,
      },
    };
  }

  async deleteCustomer(tenantId: string, customerId: string) {
    // Verify customer exists and belongs to tenant
    const existingCustomer = await this.prisma.customer.findFirst({
      where: {
        id: customerId,
        tenantId,
        // recoveryId, // Removed as it's not needed for deletion
      },
    });

    if (!existingCustomer) {
      throw new NotFoundException('Customer not found');
    }

    await this.prisma.customer.delete({
      where: { id: customerId },
    });

    this.logger.log(`✅ Customer deleted: ${customerId}`);
    return { message: 'Customer deleted successfully' };
  }

  async getCustomerStats(tenantId: string) {
    const totalCustomers = await this.prisma.customer.count({
      where: { tenantId },
    });

    const recentCustomers = await this.prisma.customer.count({
      where: {
        tenantId,
        createdAt: {
          gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // Last 30 days
        },
      },
    });

    return {
      totalCustomers,
      recentCustomers,
      growthRate: totalCustomers > 0 ? (recentCustomers / totalCustomers) * 100 : 0,
    };
  }

  async createOrUpdateCustomer(tenantId: string, customerData: CreateCustomerDto) {
    try {
      return await this.createCustomer(tenantId, customerData);
    } catch (error) {
      if (error instanceof ConflictException) {
        // Customer exists, update instead
        const existingCustomer = await this.getCustomerByEmail(tenantId, customerData.email);
        return this.updateCustomer(tenantId, existingCustomer.id, customerData);
      }
      throw error;
    }
  }
}