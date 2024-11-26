import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { UserService } from './user.service'; // Import du service utilisateur
import { UserController } from './user.controller'; // Import du contrôleur utilisateur
import { AuthService } from 'src/auth/auth.service';
import { AuthController } from 'src/auth/auth.controller';
import { user, UserSchema } from 'src/user/Schemas/user.shema'; 
import { RefreshTokenSchema } from 'src/auth/schemas/refresh-token.schema';
import { ResetTokenSchema } from 'src/auth/schemas/reset-token.schema';
import { MailModule } from 'src/services/mail.module'; // Module Mail
import { RolesModule } from 'src/roles/roles.module'; // Assurez-vous que ce chemin est correct

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: 'user', schema: UserSchema },
      { name: 'RefreshToken', schema: RefreshTokenSchema },
      { name: 'ResetToken', schema: ResetTokenSchema },
    ]),
    MailModule, // Module pour l'envoi d'emails
    RolesModule, // Gestion des rôles
  ],
  controllers: [UserController, AuthController], // Ajout du UserController et AuthController
  providers: [UserService, AuthService], // Ajout des services UserService et AuthService
  exports: [UserService, AuthService, MongooseModule], // Export des services nécessaires
})
export class UserModule {}