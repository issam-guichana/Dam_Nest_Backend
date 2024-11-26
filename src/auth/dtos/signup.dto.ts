import { IsEmail, IsString, Matches, MinLength, IsOptional } from 'class-validator';

export class SignupDto {
  @IsString()
  name: string;

  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  @Matches(/^(?=.*[0-9])/, { message: 'Password must contain at least one number' })
  password: string;

  @IsString()
  @MinLength(6)
  @Matches(/^(?=.*[0-9])/, { message: 'Password must contain at least one number' })
  confirmPassword: string;

  @IsOptional()  // Marked as optional, since it's not always provided
  @IsString()
  roleId?: string;  // Make roleId optional as it's not always required in the signup
}
