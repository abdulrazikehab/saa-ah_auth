// src/customers/customers.controller.ts
import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  Request,
  ParseIntPipe,
  HttpCode,
  HttpStatus,
  Req,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { JwtAuthGuard } from '../guard/jwt-auth.guard';
import { CustomersService, CreateCustomerDto, UpdateCustomerDto } from './customers.service';
import { PrismaService } from '../../prisma/prisma.service';

@Controller('customers')
export class CustomersController {
  constructor(
    private readonly customersService: CustomersService,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * Public endpoint for customer signup (storefront users)
   */
  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  async customerSignup(
    @Body() signupDto: { email: string; password: string; firstName?: string; lastName?: string; phone?: string },
    @Req() req: any,
  ) {
    // Extract tenant from header, subdomain, or use default
    // Use the same tenant resolution logic as login for consistency
    let tenantId = req.headers['x-tenant-id'] 
      || req.headers['x-tenant-domain'] 
      || req.tenantId;
    
    // If tenantId is a domain (like "localhost" or "market.saeaa.com"), try to resolve it
    if (tenantId && tenantId !== 'default') {
      try {
        let subdomain = tenantId;
        // Extract subdomain from domain (e.g., "market.saeaa.com" -> "market")
        if (tenantId.includes('.')) {
          const parts = tenantId.split('.');
          // If it's a subdomain format (e.g., market.saeaa.com), first part is subdomain
          // If it's just localhost, use as is
          if (tenantId.includes('localhost')) {
            subdomain = parts[0] || 'default';
          } else {
            subdomain = parts[0] || tenantId;
          }
        }
        
        // Try to find tenant by subdomain or ID
        const tenant = await this.prisma.tenant.findFirst({
          where: {
            OR: [
              { subdomain },
              { id: tenantId },
              { id: subdomain },
            ],
          },
        });
        
        if (tenant) {
          tenantId = tenant.id;
        } else {
          // If no tenant found, try to find customer by email to get their tenant
          // This handles cases where customer was created with different tenant
          const existingCustomer = await this.prisma.customer.findFirst({
            where: {
              email: signupDto.email.toLowerCase().trim(),
            },
          });
          
          if (existingCustomer) {
            // Customer exists, return conflict
            throw new ConflictException('Customer with this email already exists');
          } else {
            // No customer found, use default tenant for new signup
            tenantId = 'default';
          }
        }
      } catch (error) {
        // If it's already a ConflictException, re-throw it
        if (error instanceof ConflictException) {
          throw error;
        }
        this.logger.error(`Error resolving tenant for signup: ${error}`);
        tenantId = 'default';
      }
    }
    
    // Fallback to default if still not set
    if (!tenantId) {
      tenantId = 'default';
    }
    
    const ipAddress = req.ip || req.connection?.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
    return this.customersService.customerSignup(tenantId, signupDto, ipAddress);
  }

  /**
   * Public endpoint for customer login (storefront users)
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async customerLogin(
    @Body() loginDto: { email: string; password: string },
    @Req() req: any,
  ) {
    // Extract tenant from header, subdomain, or use default
    // Also check X-Tenant-Domain header which is sent by frontend
    let tenantId = req.headers['x-tenant-id'] 
      || req.headers['x-tenant-domain'] 
      || req.tenantId;
    
    // If tenantId is a domain (like "localhost" or "market.saeaa.com"), try to resolve it
    if (tenantId && tenantId !== 'default') {
      // It might be a domain, try to find tenant by subdomain
      try {
        let subdomain = tenantId;
        // Extract subdomain from domain (e.g., "market.saeaa.com" -> "market")
        if (tenantId.includes('.')) {
          const parts = tenantId.split('.');
          // If it's a subdomain format (e.g., market.saeaa.com), first part is subdomain
          // If it's just localhost, use as is
          if (tenantId.includes('localhost')) {
            subdomain = parts[0] || 'default';
          } else {
            subdomain = parts[0] || tenantId;
          }
        }
        
        // Try to find tenant by subdomain or ID
        const tenant = await this.prisma.tenant.findFirst({
          where: {
            OR: [
              { subdomain },
              { id: tenantId },
              { id: subdomain },
            ],
          },
        });
        
        if (tenant) {
          tenantId = tenant.id;
        } else {
          // If no tenant found, try to find customer by email across all tenants
          // This handles cases where customer was created with different tenant
          const customer = await this.prisma.customer.findFirst({
            where: {
              email: loginDto.email.toLowerCase().trim(),
            },
            include: { tenant: true },
          });
          
          if (customer) {
            tenantId = customer.tenantId;
            this.logger.log(`Found customer in tenant ${tenantId}, using that tenant for login`);
          } else {
            tenantId = 'default';
          }
        }
      } catch (error) {
        this.logger.error(`Error resolving tenant: ${error.message}`);
        // If lookup fails, try to find customer by email to get their tenant
        try {
          const customer = await this.prisma.customer.findFirst({
            where: {
              email: loginDto.email.toLowerCase().trim(),
            },
          });
          tenantId = customer?.tenantId || 'default';
        } catch (e) {
          tenantId = 'default';
        }
      }
    }
    
    // Fallback to default if still not set
    if (!tenantId) {
      tenantId = 'default';
    }
    
    // Normalize email
    const normalizedLoginDto = {
      email: loginDto.email?.toLowerCase().trim() || '',
      password: loginDto.password || '',
    };
    
    if (!normalizedLoginDto.email || !normalizedLoginDto.password) {
      throw new BadRequestException('Email and password are required');
    }
    
    return this.customersService.customerLogin(tenantId, normalizedLoginDto);
  }

  // Protected endpoints below (require JWT authentication)
  @Post()
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.CREATED)
  async createCustomer(
    @Request() req: any,
    @Body() createCustomerDto: CreateCustomerDto,
  ) {
    return this.customersService.createCustomer(req.user.tenantId, createCustomerDto);
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  async getCustomers(
    @Request() req: any,
    @Query('page', new ParseIntPipe({ optional: true })) page: number = 1,
    @Query('limit', new ParseIntPipe({ optional: true })) limit: number = 50,
    @Query('search') search?: string,
  ) {
    return this.customersService.getCustomers(req.user.tenantId, page, limit, search);
  }

  @Get('stats')
  @UseGuards(JwtAuthGuard)
  async getCustomerStats(@Request() req: any) {
    return this.customersService.getCustomerStats(req.user.tenantId);
  }

  @Get('email/:email')
  @UseGuards(JwtAuthGuard)
  async getCustomerByEmail(
    @Request() req: any,
    @Param('email') email: string,
  ) {
    return this.customersService.getCustomerByEmail(req.user.tenantId, email);
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  async getCustomerById(
    @Request() req: any,
    @Param('id') customerId: string,
  ) {
    return this.customersService.getCustomerById(req.user.tenantId, customerId);
  }

  @Put(':id')
  @UseGuards(JwtAuthGuard)
  async updateCustomer(
    @Request() req: any,
    @Param('id') customerId: string,
    @Body() updateCustomerDto: UpdateCustomerDto,
  ) {
    return this.customersService.updateCustomer(req.user.tenantId, customerId, updateCustomerDto);
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteCustomer(
    @Request() req: any,
    @Param('id') customerId: string,
  ) {
    return this.customersService.deleteCustomer(req.user.tenantId, customerId);
  }

  @Post('upsert')
  @UseGuards(JwtAuthGuard)
  async createOrUpdateCustomer(
    @Request() req: any,
    @Body() customerData: CreateCustomerDto,
  ) {
    return this.customersService.createOrUpdateCustomer(req.user.tenantId, customerData);
  }
}