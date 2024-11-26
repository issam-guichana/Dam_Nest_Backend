import { Body, Controller, Param, Post, Put, Query, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { ChangePasswordDto } from './dtos/change-password.dto';
import { AuthenticationGuard } from 'src/guards/authentication.guard';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { VerifyOtpDto } from 'src/auth/dtos/VerifyOtpDto';
import { ResetPasswordOtpDto } from './dtos/reset-password-otp';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signUp(@Body() signupData: SignupDto) {
    return this.authService.signup(signupData);
  }

  @Post('login')
  async login(@Body() credentials: LoginDto) {
    return this.authService.login(credentials);
  }

  @Post('google-signin')
  async googleSignIn(@Body() body: { idToken: string }) {
    const { idToken } = body;
    try {
      const sessionData = await this.authService.verifyGoogleToken(idToken);
      return {
        message: 'Google sign-in successful',
        ...sessionData,
      };
    } catch (error) {
      return {
        message: 'Google sign-in failed',
        error: error.message,
      };
    }
  }

  @UseGuards(AuthenticationGuard)
  @Put('change-password')
  async changePassword(
    @Body() changePasswordDto: ChangePasswordDto,
    @Req() req,
  ) {
    const userId = req.userId; // The userId comes from the JWT token
    return this.authService.changePassword(
      userId,
      changePasswordDto.oldPassword,
      changePasswordDto.newPassword,
    );
  }

  @Post('forgot-password')
    async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
      const response = await this.authService.forgotPassword(forgotPasswordDto.email);
      return response; // Includes userId in the response
    }


@Post('verify-otp/:userId')
  async verifyOtp(@Param('userId') userId: string, @Body() verifyOtpDto: VerifyOtpDto) {
    const { otp } = verifyOtpDto;
    return this.authService.verifyOtp(userId, otp); // Verifies OTP, returns success or failure
  }

  @Post('reset-password/:userId')
  async resetPassword(
    @Param('userId') userId: string,
    @Body() resetPasswordDto: ResetPasswordOtpDto,
  ) {
    return this.authService.resetPassword(userId, resetPasswordDto); // Resets the password
  }
}