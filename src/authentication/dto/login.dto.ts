// apps/app-auth/src/auth/dto/login.dto.ts
import { IsEmail, IsString, IsNotEmpty, IsOptional, ValidateIf } from 'class-validator';

export class LoginDto {
  @ValidateIf((obj) => !obj.username) // Required if username is not provided
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsOptional()
  email?: string;

  @ValidateIf((obj) => !obj.email) // Required if email is not provided
  @IsString({ message: 'Username must be a string' })
  @IsOptional()
  username?: string; // Subemail - the part before @ (e.g., "abdelrazikehab7" from "abdelrazikehab7@gmail.com")

  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  password!: string;

  @IsOptional()
  fingerprint?: Record<string, unknown>;
}

export class LoginResponseDto {
  id!: string;
  email!: string;
  username?: string;
  role!: string;
  tenantId!: string;
  tenantName?: string;
  tenantSubdomain?: string;
  avatar?: string | null;
  accessToken!: string;
  refreshToken!: string;
}