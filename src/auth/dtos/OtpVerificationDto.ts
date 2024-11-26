import { IsString } from "class-validator";

export class OtpVerificationDto {
    @IsString()
    password: string;
  
    @IsString()
    confirmPassword: string;
  }
  