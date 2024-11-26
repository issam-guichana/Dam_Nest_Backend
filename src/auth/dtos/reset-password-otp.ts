import { IsString, MinLength, Matches, IsNotEmpty } from 'class-validator';

export class ResetPasswordOtpDto {
  @IsString()
  @MinLength(6)
  @Matches(/^(?=.*[0-9])/, { message: 'Password must contain at least one number' })
  password: string; // New password


}
