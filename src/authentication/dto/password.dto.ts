// apps/app-auth/src/auth/dto/password.dto.ts
import { IsEmail, IsString, MinLength, Matches, IsNotEmpty } from 'class-validator';

export class ForgotPasswordDto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email!: string;
}

export class ResetPasswordDto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email!: string;

  @IsString({ message: 'Reset code must be a string' })
  @IsNotEmpty({ message: 'Reset code is required' })
  @Matches(/^\d{6}$/, { message: 'Reset code must be exactly 6 digits' })
  code!: string;

  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
    message: 'Password must contain at least one uppercase letter, one lowercase letter, and one number'
  })
  newPassword!: string;
}

export class VerifyCodeDto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email!: string;

  @IsString({ message: 'Reset code must be a string' })
  @IsNotEmpty({ message: 'Reset code is required' })
  @Matches(/^\d{6}$/, { message: 'Reset code must be exactly 6 digits' })
  code!: string;
}