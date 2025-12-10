import { Injectable, ForbiddenException, NotFoundException, ConflictException, BadRequestException, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcryptjs';

export interface CreateStaffDto {
  email: string;
  password: string;
  name?: string;
  permissions: string[];
}

export interface UpdateStaffDto {
  email?: string;
  name?: string;
  permissions?: string[];
}

@Injectable()
export class StaffService {
  private readonly logger = new Logger(StaffService.name);

  constructor(private prismaService: PrismaService) {}

  /**
   * Create a new staff user
   */
  async createStaff(tenantId: string, creatingUserId: string, staffData: CreateStaffDto) {
    // Verify creating user has permission
    const creatingUser = await this.prismaService.user.findFirst({
      where: { 
        id: creatingUserId,
        tenantId,
        role: { in: ['SUPER_ADMIN', 'SHOP_OWNER'] }
      },
    });

    if (!creatingUser) {
      throw new ForbiddenException('Insufficient permissions to create staff users');
    }

    // Check if user already exists
    const existingUser = await this.prismaService.user.findUnique({
      where: { email: staffData.email },
    });

    if (existingUser) {
      throw new ConflictException('User already exists');
    }

    // Hash password
    const password = staffData.password || Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create staff user and permissions in transaction
    const result = await this.prismaService.$transaction(async (tx: { user: { create: (arg0: { data: { email: string; password: string; role: string; tenantId: string; }; }) => any; }; staffPermission: { create: (arg0: { data: { userId: any; tenantId: string; permission: string; grantedBy: string; }; }) => any; }; }) => {
      // Create user as staff
      const user = await tx.user.create({
        data: {
          email: staffData.email,
          password: hashedPassword,
          role: 'STAFF',
          tenantId,
        },
      });

      // Create staff permissions
      const permissions = await Promise.all(
        staffData.permissions.map(permission =>
          tx.staffPermission.create({
            data: {
              userId: user.id,
              tenantId,
              permission,
              grantedBy: creatingUserId,
            },
          })
        )
      );

      return { user, permissions };
    });

    // Log staff creation
    await this.logAuditEvent(
      creatingUserId,
      tenantId,
      'STAFF_CREATED',
      result.user.id,
      'user',
      undefined,
      { permissions: staffData.permissions },
      { staffEmail: staffData.email }
    );

    this.logger.log(`✅ Staff user created: ${staffData.email} by user: ${creatingUserId}`);

    return {
      id: result.user.id,
      email: result.user.email,
      permissions: staffData.permissions,
      createdAt: result.user.createdAt,
    };
  }

  /**
   * Get all staff users for a tenant
   */
  async getStaffUsers(tenantId: string, page: number = 1, limit: number = 50) {
    const skip = (page - 1) * limit;

    const [staffUsers, total] = await Promise.all([
      this.prismaService.user.findMany({
        where: {
          tenantId,
          role: 'STAFF',
        },
        select: {
          id: true,
          email: true,
          createdAt: true,
          updatedAt: true,
          staffPermissions: {
            select: {
              permission: true,
              grantedAt: true,
              grantedBy: true,
            },
          },
        },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      this.prismaService.user.count({
        where: {
          tenantId,
          role: 'STAFF',
        },
      }),
    ]);

    return {
      data: staffUsers,
      meta: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  /**
   * Get a specific staff user
   */
  async getStaffUser(tenantId: string, staffUserId: string) {
    const staffUser = await this.prismaService.user.findFirst({
      where: {
        id: staffUserId,
        tenantId,
        role: 'STAFF',
      },
      select: {
          id: true,
          email: true,
          createdAt: true,
          updatedAt: true,
          staffPermissions: {
            select: {
              permission: true,
              grantedAt: true,
              grantedBy: true,
            },
          },
        },
    });

    if (!staffUser) {
      throw new NotFoundException('Staff user not found');
    }

    return staffUser;
  }

  /**
   * Update staff user permissions
   */
  async updateStaffPermissions(
    tenantId: string, 
    updatingUserId: string, 
    staffUserId: string, 
    permissions: string[]
  ) {
    // Verify updating user has permission
    const updatingUser = await this.prismaService.user.findFirst({
      where: { 
        id: updatingUserId,
        tenantId,
        role: { in: ['SUPER_ADMIN', 'SHOP_OWNER'] }
      },
    });

    if (!updatingUser) {
      throw new ForbiddenException('Insufficient permissions to update staff permissions');
    }

    // Verify staff user exists and belongs to tenant
    const staffUser = await this.prismaService.user.findFirst({
      where: { 
        id: staffUserId,
        tenantId,
        role: 'STAFF'
      },
    });

    if (!staffUser) {
      throw new NotFoundException('Staff user not found');
    }

    // Update permissions in transaction
    const result = await this.prismaService.$transaction(async (tx: { staffPermission: { deleteMany: (arg0: { where: { userId: string; tenantId: string; }; }) => any; create: (arg0: { data: { userId: string; tenantId: string; permission: string; grantedBy: string; }; }) => any; }; }) => {
      // Remove existing permissions
      await tx.staffPermission.deleteMany({
        where: {
          userId: staffUserId,
          tenantId,
        },
      });

      // Create new permissions
      const newPermissions = await Promise.all(
        permissions.map(permission =>
          tx.staffPermission.create({
            data: {
              userId: staffUserId,
              tenantId,
              permission,
              grantedBy: updatingUserId,
            },
          })
        )
      );

      return newPermissions;
    });

    // Log permission update
    await this.logAuditEvent(
      updatingUserId,
      tenantId,
      'STAFF_PERMISSIONS_UPDATED',
      staffUserId,
      'user',
      undefined,
      { permissions },
      { staffEmail: staffUser.email }
    );

    this.logger.log(`✅ Staff permissions updated for user: ${staffUser.email} by user: ${updatingUserId}`);

    return {
      message: 'Staff permissions updated successfully',
      permissions: result.map((p: { permission: any; }) => p.permission),
    };
  }

  /**
   * Delete a staff user
   */
  async deleteStaffUser(tenantId: string, deletingUserId: string, staffUserId: string) {
    // Verify deleting user has permission
    const deletingUser = await this.prismaService.user.findFirst({
      where: { 
        id: deletingUserId,
        tenantId,
        role: { in: ['SUPER_ADMIN', 'SHOP_OWNER'] }
      },
    });

    if (!deletingUser) {
      throw new ForbiddenException('Insufficient permissions to delete staff users');
    }

    // Verify staff user exists and belongs to tenant
    const staffUser = await this.prismaService.user.findFirst({
      where: { 
        id: staffUserId,
        tenantId,
        role: 'STAFF'
      },
    });

    if (!staffUser) {
      throw new NotFoundException('Staff user not found');
    }

    // Prevent self-deletion
    if (staffUserId === deletingUserId) {
      throw new BadRequestException('Cannot delete your own account');
    }

    // Delete staff user and related data in transaction
    await this.prismaService.$transaction(async (tx: { staffPermission: { deleteMany: (arg0: { where: { userId: string; tenantId: string; }; }) => any; }; refreshToken: { deleteMany: (arg0: { where: { userId: string; }; }) => any; }; user: { delete: (arg0: { where: { id: string; }; }) => any; }; }) => {
      // Delete staff permissions
      await tx.staffPermission.deleteMany({
        where: {
          userId: staffUserId,
          tenantId,
        },
      });

      // Delete refresh tokens
      await tx.refreshToken.deleteMany({
        where: {
          userId: staffUserId,
        },
      });

      // Delete the user
      await tx.user.delete({
        where: {
          id: staffUserId,
        },
      });
    });

    // Log staff deletion
    await this.logAuditEvent(
      deletingUserId,
      tenantId,
      'STAFF_DELETED',
      staffUserId,
      'user',
      undefined,
      undefined,
      { staffEmail: staffUser.email }
    );

    this.logger.log(`✅ Staff user deleted: ${staffUser.email} by user: ${deletingUserId}`);

    return {
      message: 'Staff user deleted successfully',
    };
  }

  /**
   * Get available permissions
   */
  getAvailablePermissions(): string[] {
    return [
      // Product permissions
      'product:create',
      'product:read', 
      'product:update',
      'product:delete',
      'product:manage',

      // Order permissions
      'order:create',
      'order:read',
      'order:update',
      'order:delete',
      'order:manage',

      // Customer permissions
      'customer:create',
      'customer:read',
      'customer:update',
      'customer:delete',
      'customer:manage',

      // Inventory permissions
      'inventory:read',
      'inventory:update',
      'inventory:manage',

      // Analytics permissions
      'analytics:read',
      'analytics:manage',

      // Settings permissions
      'settings:read',
      'settings:update',
    ];
  }

  /**
   * Check if a staff user has specific permission
   */
  async hasPermission(userId: string, tenantId: string, permission: string): Promise<boolean> {
    const user = await this.prismaService.user.findFirst({
      where: { id: userId, tenantId },
    });

    if (!user) {
      return false;
    }

    // Super admins and shop owners have all permissions
    if (user.role === 'SUPER_ADMIN' || user.role === 'SHOP_OWNER') {
      return true;
    }

    // Check specific permission for staff
    const hasPermission = await this.prismaService.staffPermission.findFirst({
      where: {
        userId,
        tenantId,
        permission,
      },
    });

    return !!hasPermission;
  }

  /**
   * Get staff user permissions
   */
  async getUserPermissions(userId: string, tenantId: string): Promise<string[]> {
    const permissions = await this.prismaService.staffPermission.findMany({
      where: {
        userId,
        tenantId,
      },
      select: { permission: true },
    });

    return permissions.map((p: { permission: any; }) => p.permission);
  }

  private async logAuditEvent(
    userId: string,
    tenantId: string,
    action: string,
    resourceId?: string,
    resourceType?: string,
    oldValues?: any,
    newValues?: any,
    metadata?: any,
  ): Promise<void> {
    try {
      await this.prismaService.auditLog.create({
        data: {
          userId,
          tenantId,
          action,
          resourceId,
          resourceType,
          oldValues,
          newValues,
          metadata,
        },
      });
    } catch (error) {
      this.logger.error('Failed to log audit event:', error);
    }
  }
}