import { IsEmail, IsNotEmpty, IsString, MinLength, Matches } from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6) // Longueur minimum du mot de passe
  password: string;

  @IsString()
  confirmPassword: string;

  @IsString()
  name: string;
}
