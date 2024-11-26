import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { UserModule } from '../user/user.module'; // Adjust the path accordingly
import { RolesModule } from '../roles/roles.module'; // Import the RolesModule
import { RefreshToken, RefreshTokenSchema } from './schemas/refresh-token.schema';
import { ResetToken, ResetTokenSchema } from 'src/auth/schemas/reset-token.schema';
import { MailService } from 'src/services/mail.service';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: RefreshToken.name, schema: RefreshTokenSchema }]),
    MongooseModule.forFeature([{ name: ResetToken.name, schema: ResetTokenSchema }]),
    JwtModule.register({
      secret: 'secret key', // Update with your secret
      signOptions: { expiresIn: '10h' },
    }),
    
    UserModule, // Ensure UserModule is imported here
    RolesModule, // Ensure RolesModule is imported here
  ],
  providers: [AuthService, MailService],
  controllers: [AuthController],
})
export class AuthModule {}
