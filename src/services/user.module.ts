import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { UserService } from 'src/user/user.service';
import { UserController } from 'src/user/user.controller';
import { AuthService } from 'src/auth/auth.service';
import { AuthController } from 'src/auth/auth.controller';
import { user, UserSchema } from 'src/user/Schemas/user.shema';
import { RefreshTokenSchema } from 'src/auth/schemas/refresh-token.schema';
import { ResetTokenSchema } from 'src/auth/schemas/reset-token.schema';
import { MailModule } from '../services/mail.module';
import { RolesModule } from '../roles/roles.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: 'user', schema: UserSchema },
      { name: 'RefreshToken', schema: RefreshTokenSchema },
      { name: 'ResetToken', schema: ResetTokenSchema },
    ]),
    MailModule,
    RolesModule,
  ],
  controllers: [UserController, AuthController],
  providers: [UserService, AuthService],
  exports: [UserService, AuthService, MongooseModule],
})
export class UserModule {}
