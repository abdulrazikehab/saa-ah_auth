// apps/app-auth/src/auth/dto/signup.dto.ts
import { IsEmail, IsString, MinLength, Matches, IsNotEmpty, IsOptional } from 'class-validator';

export class SignUpDto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email!: string;

  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(6, { message: 'Password must be at least 6 characters long' })
  password!: string;

  @IsString({ message: 'Name must be a string' })
  @IsOptional()
  name?: string;

  @IsString({ message: 'Store name must be a string' })
  @IsOptional()
  storeName?: string;

  @IsString({ message: 'Subdomain must be a string' })
  @IsOptional()
  @MinLength(3, { message: 'Subdomain must be at least 3 characters long' })
  @Matches(/^[a-z0-9-]+$/, { message: 'Subdomain can only contain lowercase letters, numbers, and hyphens' })
  subdomain?: string;

  @IsOptional()
  fingerprint?: any;
}

export class SignUpResponseDto {
  id!: string;
  email!: string;
  recoveryId!: string; // Secret recovery ID for account recovery
  accessToken!: string;
  refreshToken!: string;
}