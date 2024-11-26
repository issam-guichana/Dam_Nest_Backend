import { IsString, IsNotEmpty, Length, IsEmail, Matches, MinLength } from 'class-validator';

export class VerifyOtpDto {

  @IsString()
  otp: string;

}
