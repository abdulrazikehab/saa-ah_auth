// src/staff/staff.controller.ts
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
  HttpCode,
  HttpStatus,
  ParseIntPipe,
  Request
} from '@nestjs/common';
import { StaffService } from './staff.service';
import { JwtAuthGuard } from '../authentication/guard/jwt-auth.guard';

@Controller('staff')
@UseGuards(JwtAuthGuard)
export class StaffController {
  constructor(private readonly staffService: StaffService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async createStaff(
    @Request() req: any,
    @Body() createStaffDto: any,
  ) {
    return this.staffService.createStaff(
      req.user.tenantId,
      req.user.id,
      createStaffDto
    );
  }

  @Get()
  async getStaffUsers(
    @Request() req: any,
    @Query('page', new ParseIntPipe({ optional: true })) page: number = 1,
    @Query('limit', new ParseIntPipe({ optional: true })) limit: number = 50,
  ) {
    return this.staffService.getStaffUsers(req.user.tenantId, page, limit);
  }

  @Get('permissions')
  async getAvailablePermissions() {
    return this.staffService.getAvailablePermissions();
  }

  @Get(':id')
  async getStaffUser(
    @Request() req: any,
    @Param('id') staffUserId: string,
  ) {
    return this.staffService.getStaffUser(req.user.tenantId, staffUserId);
  }

  @Put(':id/permissions')
  async updateStaffPermissions(
    @Request() req: any,
    @Param('id') staffUserId: string,
    @Body('permissions') permissions: string[],
  ) {
    return this.staffService.updateStaffPermissions(
      req.user.tenantId,
      req.user.id,
      staffUserId,
      permissions
    );
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteStaffUser(
    @Request() req: any,
    @Param('id') staffUserId: string,
  ) {
    return this.staffService.deleteStaffUser(
      req.user.tenantId,
      req.user.id,
      staffUserId
    );
  }
}