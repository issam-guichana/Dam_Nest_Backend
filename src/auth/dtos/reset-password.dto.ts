import { IsString, Matches, MinLength } from 'class-validator';

export class ResetPasswordDto {

  @IsString()
  @Matches(/^\d{4}$/, { message: 'OTP must contain only digits' })
  otp: string;

}
