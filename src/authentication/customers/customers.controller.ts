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
} from '@nestjs/common';
import { JwtAuthGuard } from '../guard/jwt-auth.guard';
import { CustomersService, CreateCustomerDto, UpdateCustomerDto } from './customers.service';

@Controller('customers')
export class CustomersController {
  constructor(private readonly customersService: CustomersService) {}

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
    const tenantId = req.headers['x-tenant-id'] || req.tenantId || 'default';
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
    const tenantId = req.headers['x-tenant-id'] || req.tenantId || 'default';
    return this.customersService.customerLogin(tenantId, loginDto);
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