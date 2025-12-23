// src/customers/customers.service.ts
import { Injectable, Logger, NotFoundException, ConflictException, UnauthorizedException, BadRequestException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { validateEmailWithMx, generateRecoveryId } from '../../utils/email-validator';
import { checkIpReputation } from '../../utils/ip-checker';
import { EmailService } from '../../email/email.service';

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
    private emailService: EmailService,
  ) {}

  /**
   * Generate 6-digit OTP code
   */
  private generateResetCode(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  /**
   * Customer signup for storefront users - sends OTP for verification
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

    // Normalize email
    const normalizedEmail = signupDto.email.toLowerCase().trim();

    // Validate email - check for fake/disposable emails
    const emailValidation = await validateEmailWithMx(normalizedEmail);
    if (!emailValidation.isValid) {
      this.logger.warn(`Customer signup with invalid email: ${normalizedEmail} - ${emailValidation.reason}`);
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

    // Check if customer already exists - first check in this tenant, then across all tenants
    const existingCustomerInTenant = await this.prisma.customer.findUnique({
      where: {
        tenantId_email: {
          tenantId: actualTenantId,
          email: normalizedEmail,
        },
      },
    });

    if (existingCustomerInTenant) {
      throw new ConflictException('Customer with this email already exists in this store');
    }

    // Also check across all tenants to provide better error message
    const existingCustomerAnywhere = await this.prisma.customer.findFirst({
      where: {
        email: normalizedEmail,
      },
    });

    if (existingCustomerAnywhere) {
      // Customer exists but in different tenant - suggest they try logging in
      throw new ConflictException('An account with this email already exists. Please try logging in instead.');
    }

    // Check for existing pending signup
    const existingPending = await this.prisma.passwordReset.findFirst({
      where: {
        email: normalizedEmail,
        used: false,
        expiresAt: {
          gt: new Date(),
        },
        code: {
          startsWith: 'CUSTOMER_SIGNUP_',
        },
      },
    });

    if (existingPending) {
      // Allow resending OTP by deleting the old pending signup and creating a new one
      this.logger.log(`Found existing pending customer signup for ${normalizedEmail}, cleaning up and allowing new signup...`);
      await this.prisma.passwordReset.delete({
        where: { id: existingPending.id },
      });
    }

    // Generate OTP code (mark with CUSTOMER_SIGNUP_ prefix)
    const verificationCode = this.generateResetCode();
    const signupCode = `CUSTOMER_SIGNUP_${verificationCode}`;
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // Hash password before storing
    const hashedPassword = await bcrypt.hash(signupDto.password, 12);

    // Store signup data temporarily in passwordReset table
    const signupData = {
      email: normalizedEmail,
      password: hashedPassword,
      firstName: signupDto.firstName,
      lastName: signupDto.lastName,
      phone: signupDto.phone,
      tenantId: actualTenantId,
    };

    // Store in passwordReset table with signup data
    try {
      await this.prisma.passwordReset.create({
        data: {
          email: normalizedEmail,
          code: signupCode,
          expiresAt,
          signupData: JSON.stringify(signupData),
        },
      });
    } catch (dbError) {
      this.logger.warn(`Failed to store signupData in DB (schema might be outdated), falling back to basic create: ${dbError}`);
      // Fallback: Try creating without signupData
      await this.prisma.passwordReset.create({
        data: {
          email: normalizedEmail,
          code: signupCode,
          expiresAt,
        },
      });
    }

    // Send verification email with the actual OTP
    let emailSent = false;
    let emailError: any = null;
    let emailResult: any = null;
    
    try {
      this.logger.log(`📧 ========================================`);
      this.logger.log(`📧 SENDING CUSTOMER SIGNUP OTP EMAIL`);
      this.logger.log(`📧 To: ${normalizedEmail}`);
      this.logger.log(`📧 Code: ${verificationCode}`);
      this.logger.log(`📧 ========================================`);
      
      try {
        emailResult = await this.emailService.sendVerificationEmail(normalizedEmail, verificationCode);
        emailSent = true;
        
        this.logger.log(`✅ Email service returned successfully`);
        this.logger.log(`✅ Message ID: ${emailResult.messageId}`);
        this.logger.log(`✅ Is Test Email: ${emailResult.isTestEmail}`);
        
        if (emailResult.previewUrl) {
          this.logger.log(`🔗 PREVIEW URL: ${emailResult.previewUrl}`);
        }
        
        // If using test email service (Ethereal), always log the preview URL and code
        if (emailResult.previewUrl || emailResult.isTestEmail) {
          this.logger.log(`📧 EMAIL PREVIEW URL: ${emailResult.previewUrl || 'Will be available after sending'}`);
          this.logger.warn(`⚠️ Using test email service (Ethereal). Verification code: ${verificationCode}`);
          if (emailResult.previewUrl) {
            this.logger.warn(`⚠️ Open this URL to see the email: ${emailResult.previewUrl}`);
          }
        } else {
          this.logger.log(`✅ Email sent to real inbox: ${normalizedEmail}`);
        }
      } catch (emailError: any) {
        this.logger.error(`❌ Email sending failed (non-blocking): ${emailError.message}`);
        // Don't block signup if email fails - user can request resend later
        if (process.env.NODE_ENV === 'development') {
          this.logger.warn(`⚠️ Development: Verification code is ${verificationCode} (email failed)`);
        }
        emailResult = { messageId: 'failed', previewUrl: '', isTestEmail: false };
      }
    } catch (error) {
      emailError = error;
      this.logger.error('❌ Failed to send verification email:', error);
      
      // In development, allow signup to continue but return the code
      if (process.env.NODE_ENV === 'development') {
        this.logger.warn(`⚠️ Development mode: Email sending failed, but continuing with code: ${verificationCode}`);
        emailSent = false;
      } else {
        // In production, clean up and throw error to prevent account creation
        await this.prisma.passwordReset.deleteMany({
          where: { email: normalizedEmail, code: signupCode },
        });
        throw new BadRequestException(`Failed to send verification email: ${error instanceof Error ? error.message : 'Unknown error'}. Please check SMTP configuration or try again later.`);
      }
    }

    this.logger.log(`📧 OTP sent for customer signup: ${normalizedEmail} (account will be created AFTER OTP verification)`);

    // IMPORTANT: NO CUSTOMER IS CREATED YET!
    // Customer account will ONLY be created in verifyCustomerSignupCode() after successful OTP verification
    const response: any = {
      email: normalizedEmail,
      emailVerified: false,
      verificationCodeSent: emailSent,
      verificationCode: verificationCode, // Always return code for development/testing
    };

    if (emailSent && emailResult) {
      if (emailResult.isTestEmail || emailResult.previewUrl) {
        response.emailPreviewUrl = emailResult.previewUrl;
        response.isTestEmail = true;
        response.emailWarning = 'Using test email service. Check preview URL or use code below.';
      }
    }
    
    if (!emailSent && emailError) {
      response.emailError = emailError instanceof Error ? emailError.message : 'Email sending failed';
      response.emailWarning = 'Email sending failed, but you can use the code above to verify.';
    }
    
    this.logger.log(`✅ Customer signup completed for: ${normalizedEmail} - NO CUSTOMER CREATED (waiting for OTP verification)`);
    this.logger.log(`📋 OTP Code: ${verificationCode} (customer must verify before account creation)`);
    
    return response;
  }

  /**
   * Verify customer signup OTP code and create customer account
   */
  async verifyCustomerSignupCode(email: string, code: string): Promise<{ valid: boolean; message: string; token?: string; customer?: any; recoveryId?: string }> {
    // Normalize email
    const normalizedEmail = email.toLowerCase().trim();
    
    // Find the signup verification code (with CUSTOMER_SIGNUP_ prefix)
    const signupCode = `CUSTOMER_SIGNUP_${code}`;
    
    this.logger.log(`🔍 Verifying customer signup code for ${normalizedEmail}: ${signupCode}`);
    
    const resetRecord = await this.prisma.passwordReset.findFirst({
      where: {
        email: normalizedEmail,
        code: signupCode,
        used: false,
        expiresAt: {
          gt: new Date(), // Not expired
        },
      },
      select: {
        id: true,
        email: true,
        code: true,
        expiresAt: true,
        used: true,
        signupData: true,
      },
    });

    if (!resetRecord) {
      return {
        valid: false,
        message: 'Invalid or expired verification code',
      };
    }

    // Get signup data from database
    let signupData: any = null;
    if (resetRecord.signupData) {
      try {
        signupData = JSON.parse(resetRecord.signupData);
        this.logger.log(`✅ Retrieved customer signup data from database for: ${normalizedEmail}`);
      } catch (parseError) {
        this.logger.error(`❌ Failed to parse signup data from database for ${normalizedEmail}: ${parseError}`);
        return {
          valid: false,
          message: 'Signup session expired. Please sign up again.',
        };
      }
    }

    if (!signupData) {
      this.logger.error(`❌ Signup data not found for: ${normalizedEmail}_${code}`);
      return {
        valid: false,
        message: 'Signup session expired. Please sign up again.',
      };
    }

    // Re-check if customer already exists (race condition protection)
    const existingCustomer = await this.prisma.customer.findFirst({
      where: {
        email: normalizedEmail,
        tenantId: signupData.tenantId,
      },
    });

    if (existingCustomer) {
      // Mark the reset record as used
      await this.prisma.passwordReset.update({
        where: { id: resetRecord.id },
        data: { used: true },
      });
      return {
        valid: false,
        message: 'Customer with this email already exists in this store',
      };
    }

    // Generate recovery ID
    const recoveryId = generateRecoveryId();

    // Create customer with password in metadata
    const customer = await this.prisma.customer.create({
      data: {
        tenantId: signupData.tenantId,
        email: normalizedEmail,
        phone: signupData.phone,
        firstName: signupData.firstName,
        lastName: signupData.lastName,
        recoveryId,
        metadata: JSON.stringify({ password: signupData.password }),
      },
    });

    // Mark the reset record as used
    await this.prisma.passwordReset.update({
      where: { id: resetRecord.id },
      data: { used: true },
    });

    // Generate JWT token
    const token = this.jwtService.sign({
      sub: customer.id,
      email: customer.email,
      tenantId: customer.tenantId,
      type: 'customer',
    });

    this.logger.log(`✅ Customer created after OTP verification: ${customer.id}`);

    return {
      valid: true,
      message: 'Email verified successfully. Account created.',
      token,
      customer: {
        id: customer.id,
        email: customer.email,
        firstName: customer.firstName,
        lastName: customer.lastName,
        phone: customer.phone,
      },
      recoveryId,
    };
  }

  /**
   * Resend customer signup verification code
   */
  async resendCustomerVerificationCode(email: string): Promise<{ success: boolean; message: string; verificationCode?: string }> {
    const normalizedEmail = email.toLowerCase().trim();
    
    // Find existing pending signup
    const existingPending = await this.prisma.passwordReset.findFirst({
      where: {
        email: normalizedEmail,
        used: false,
        expiresAt: {
          gt: new Date(),
        },
        code: {
          startsWith: 'CUSTOMER_SIGNUP_',
        },
      },
    });

    if (!existingPending) {
      return {
        success: false,
        message: 'No pending signup found. Please sign up again.',
      };
    }

    // Extract the code from the stored code (remove CUSTOMER_SIGNUP_ prefix)
    const storedCode = existingPending.code.replace('CUSTOMER_SIGNUP_', '');
    
    // Send verification email
    let emailSent = false;
    try {
      await this.emailService.sendVerificationEmail(normalizedEmail, storedCode);
      emailSent = true;
      this.logger.log(`✅ Resent verification email to ${normalizedEmail}`);
    } catch (error) {
      this.logger.error(`❌ Failed to resend verification email: ${error}`);
      if (process.env.NODE_ENV === 'development') {
        // In development, return the code even if email fails
        return {
          success: true,
          message: 'Verification code (email sending failed, but here is the code):',
          verificationCode: storedCode,
        };
      }
      return {
        success: false,
        message: 'Failed to resend verification email. Please try again later.',
      };
    }

    return {
      success: true,
      message: 'Verification code resent successfully',
      verificationCode: process.env.NODE_ENV === 'development' ? storedCode : undefined,
    };
  }

  /**
   * Customer login for storefront users
   */
  async customerLogin(tenantId: string, loginDto: { email: string; password: string }) {
    this.logger.log(`Customer login attempt for tenant: ${tenantId}, email: ${loginDto.email}`);

    // Try to resolve tenant if 'default' is used
    let requestedTenantId = tenantId;
    if (tenantId === 'default') {
      const tenant = await this.prisma.tenant.findFirst({
        where: {
          OR: [
            { id: 'default' },
            { subdomain: 'default' },
          ],
        },
      });
      requestedTenantId = tenant?.id || 'default';
    }

    // Normalize email
    const normalizedEmail = loginDto.email.toLowerCase().trim();

    // 1. Find customer in the requested tenant first
    let customer = await this.prisma.customer.findUnique({
      where: {
        tenantId_email: {
          tenantId: requestedTenantId,
          email: normalizedEmail,
        },
      },
    });

    // 2. If not found in requested tenant, search across all tenants
    if (!customer) {
      this.logger.log(`Customer not found in tenant ${requestedTenantId}, searching across all tenants...`);
      const existingCustomerAnywhere = await this.prisma.customer.findFirst({
        where: {
          email: normalizedEmail,
        },
      });
      
      if (existingCustomerAnywhere) {
        this.logger.log(`Found customer in different tenant: ${existingCustomerAnywhere.tenantId}. Verifying password before linking...`);
        
        // Verify password of the existing customer
        let metadata: { password?: string } = {};
        try {
          metadata = typeof existingCustomerAnywhere.metadata === 'string' 
            ? JSON.parse(existingCustomerAnywhere.metadata) 
            : existingCustomerAnywhere.metadata as { password?: string };
        } catch (error) {
          this.logger.error('Failed to parse customer metadata:', error);
          throw new UnauthorizedException('Invalid credentials');
        }

        if (!metadata.password) {
          throw new UnauthorizedException('Invalid credentials');
        }

        const isPasswordValid = await bcrypt.compare(loginDto.password, metadata.password);
        if (!isPasswordValid) {
          throw new UnauthorizedException('Invalid email or password');
        }

        // Password is valid! Now "insert in merchant table" (link to current tenant)
        this.logger.log(`✅ Password valid. Creating customer record for tenant ${requestedTenantId}...`);
        try {
          customer = await this.prisma.customer.create({
            data: {
              tenantId: requestedTenantId,
              email: normalizedEmail,
              firstName: existingCustomerAnywhere.firstName,
              lastName: existingCustomerAnywhere.lastName,
              phone: existingCustomerAnywhere.phone,
              recoveryId: generateRecoveryId(), // New recovery ID for this store
              metadata: existingCustomerAnywhere.metadata as any, // Copy password/metadata
            },
          });
          this.logger.log(`✅ Customer linked to tenant ${requestedTenantId}: ${customer.id}`);
        } catch (error: any) {
          this.logger.error(`Failed to link customer to tenant ${requestedTenantId}: ${error.message}`);
          // If creation fails (e.g. race condition), try to fetch again
          customer = await this.prisma.customer.findUnique({
            where: {
              tenantId_email: {
                tenantId: requestedTenantId,
                email: normalizedEmail,
              },
            },
          });
          
          if (!customer) {
            // If still not found, use the existing one from other tenant for this session
            customer = existingCustomerAnywhere;
          }
        }
      }
    }

    if (!customer) {
      this.logger.warn(`Customer not found: ${normalizedEmail} in any tenant`);
      throw new UnauthorizedException('Invalid email or password. Please check your credentials or sign up if you don\'t have an account.');
    }

    // 3. Final password verification (if we didn't already do it above)
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

    const isPasswordValid = await bcrypt.compare(loginDto.password, metadata.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    // Generate JWT token
    const token = this.jwtService.sign({
      sub: customer.id,
      email: customer.email,
      tenantId: customer.tenantId,
      type: 'customer',
    });

    this.logger.log(`✅ Customer logged in: ${customer.id} (Tenant: ${customer.tenantId})`);

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