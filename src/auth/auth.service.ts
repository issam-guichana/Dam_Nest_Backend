import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from 'src/auth/schemas/user.schema';
import { UserModule } from 'src/user/user.module';
import mongoose, { Model, Types } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid';
import { ResetToken, ResetTokenDocument } from './schemas/reset-token.schema';
import { MailService } from 'src/services/mail.service';
import { RolesService } from 'src/roles/roles.service';
import { HttpException, HttpStatus } from '@nestjs/common';
import { OtpVerificationDto } from './dtos/OtpVerificationDto';
import * as otpGenerator from 'otp-generator';
import { OAuth2Client } from 'google-auth-library';
import { ResetPasswordOtpDto } from './dtos/reset-password-otp';

@Injectable()
export class AuthService {
  private googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
  constructor(
    @InjectModel('user') private UserModel: Model<User>,
    @InjectModel(RefreshToken.name) private RefreshTokenModel: Model<RefreshToken>,
    @InjectModel(ResetToken.name) private ResetTokenModel: Model<ResetTokenDocument>,
    private jwtService: JwtService,
    private mailService: MailService,
    private rolesService: RolesService,
  ) {}

 
  async verifyGoogleToken(idToken: string) {
    try {
      const ticket = await this.googleClient.verifyIdToken({
        idToken,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
  
      const payload = ticket.getPayload();
      if (!payload) {
        throw new UnauthorizedException('Invalid Google ID token');
      }
  
      const { sub, email, name, picture } = payload;
  
      const user = await this.findOrCreateUser({ sub, email, name, picture });
      if (!user) {
        throw new InternalServerErrorException('User could not be created or retrieved');
      }
  
      const tokens = await this.generateUserTokens(user._id);
  
      return {
        userId: user._id,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };
    } catch (error) {
      console.error('Error in verifyGoogleToken:', error);
      throw new InternalServerErrorException('Google token verification failed');
    }
  }

  private async findOrCreateUser({ sub, email, name, picture }: { sub: string, email: string, name: string, picture: string }) {
    try {
      let user = await this.UserModel.findOne({ email });
  
      if (!user) {
        // Generate a random password for Google users
        const randomPassword = uuidv4();
        const hashedPassword = await bcrypt.hash(randomPassword, 10);
        const defaultRoleId = new mongoose.Types.ObjectId("609d1e90fdb3a2421cfa7d55");

        // Create new user with required fields
        user = new this.UserModel({
          googleId: sub,
          email,
          name,
          profilePicture: picture,
          password: hashedPassword,
          confirmPassword: hashedPassword, // Set the same hashed password
          roleId: defaultRoleId,
          otpVerified: true
        });
  
        await user.save();
      }
  
      return user;
    } catch (error) {
      console.error('Error in findOrCreateUser:', error);
      throw new InternalServerErrorException('Failed to find or create user');
    }
  }
    
  async forgotPassword(email: string) {
    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Delete any previous OTP tokens
    await this.ResetTokenModel.deleteMany({ userId: user._id });

    const otp = otpGenerator.generate(4, { digits: true, upperCaseAlphabets: false, lowerCaseAlphabets: false, specialChars: false });
    const expiryDate = new Date();
    expiryDate.setHours(expiryDate.getHours() + 1); // OTP expires in 1 hour

    const resetToken = await this.ResetTokenModel.create({
      userId: user._id,
      otp,
      expiryDate,
      token: uuidv4(), // Generate a unique token
    });

    await this.mailService.sendPasswordResetEmail(user.email, otp);

    return { message: 'Password reset OTP sent to your email', userId: user._id }; // Include userId for future verification
  }

  async verifyOtp(userId: string, otp: string) {
    // Check if the userId is a valid ObjectId or if it's an email
    let user;
    if (Types.ObjectId.isValid(userId)) {
        // If userId is a valid ObjectId, search by ObjectId
        user = await this.UserModel.findById(new Types.ObjectId(userId));
    } else {
        // If userId is not a valid ObjectId, search by email (assuming email is unique)
        user = await this.UserModel.findOne({ email: userId });
    }

    if (!user) {
        throw new NotFoundException('User not found');
    }

    // Look for the OTP in the reset token collection
    const resetToken = await this.ResetTokenModel.findOne({
        userId: user._id,  // Ensure userId in ResetToken matches the user's ObjectId
        otp,
        expiryDate: { $gt: new Date() }, // Check if OTP is still valid
    });

    if (!resetToken) {
        throw new BadRequestException('Invalid or expired OTP');
    }

    // Mark OTP as verified and delete it
    await this.ResetTokenModel.deleteOne({ _id: resetToken._id });

    return { message: 'OTP verified successfully. You can now reset your password.' };
}

  // Change the user's password after OTP verification
  async changePassword(userId: string, oldPassword: string, newPassword: string) {
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
      throw new BadRequestException('Old password is incorrect');
    }

    if (newPassword === oldPassword) {
      throw new BadRequestException('New password cannot be the same as the old password');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    return { message: 'Password changed successfully' };
  }
  

  

  async signup(signupData: SignupDto) {
    const { email, password, confirmPassword, name } = signupData;
  
    if (!email || !password || !confirmPassword || !name) {
      throw new BadRequestException('All fields are required');
    }
  
    const emailInUse = await this.UserModel.findOne({ email }).lean();
    if (emailInUse) {
      throw new BadRequestException('Email already in use');
    }
  
    if (password !== confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }
  
    const hashedPassword = await bcrypt.hash(password, 10);
    const defaultRoleId = new mongoose.Types.ObjectId("609d1e90fdb3a2421cfa7d55");
    const roleId = signupData.roleId || defaultRoleId;
  
    try {
      const newUser = await this.UserModel.create({
        name,
        email,
        password: hashedPassword,
        confirmPassword: hashedPassword,
        roleId,
      });
  
      return {
        message: 'User registered successfully',
        userId: newUser._id.toString(),
      };
    } catch (error) {
      console.error('Error creating user:', error);
      if (error instanceof mongoose.Error.ValidationError) {
        throw new BadRequestException(error.message);
      }
      throw new InternalServerErrorException('Failed to signup user');
    }
  }

  async login(credentials: LoginDto) {
    const { email, password } = credentials;
    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Wrong credentials');
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }

    const tokens = await this.generateUserTokens(user._id);
    return {
      ...tokens,
      userId: user._id,
    };
  }

  async generateUserTokens(userId) {
    const accessToken = this.jwtService.sign({ userId }, { expiresIn: '10h' });
    const refreshToken = uuidv4();

    await this.storeRefreshToken(refreshToken, userId);
    return {
      accessToken,
      refreshToken,
    };
  }

  async storeRefreshToken(token: string, userId: string) {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);

    await this.RefreshTokenModel.updateOne(
      { userId },
      { $set: { expiryDate, token } },
      { upsert: true }
    );
  }

  async getUserPermissions(userId: string) {
    const user = await this.UserModel.findById(userId);

    if (!user) throw new BadRequestException();

    const role = await this.rolesService.getRoleById(user.roleId.toString());
    return role.permissions;
  }

  async resetPassword(userIdOrEmail: string, resetPasswordDto: ResetPasswordOtpDto) {
    const { password } = resetPasswordDto;
  
    // Check if the input is a valid ObjectId or an email
    let user;
    if (Types.ObjectId.isValid(userIdOrEmail)) {
      // If input is a valid ObjectId, search by ID
      user = await this.UserModel.findById(new Types.ObjectId(userIdOrEmail));
    } else {
      // If input is not a valid ObjectId, search by email
      user = await this.UserModel.findOne({ email: userIdOrEmail });
    }
  
    if (!user) {
      throw new NotFoundException('User not found');
    }
  
    // Hash the new password before saving
    const hashedPassword = await bcrypt.hash(password, 10);
  
    // Update the user's password
    user.password = hashedPassword;
    await user.save();
  
    // Optionally, delete any reset tokens for this user (security measure)
    await this.ResetTokenModel.deleteMany({ userId: user._id });
  
    return { message: 'Password successfully reset' };
  }
  
}