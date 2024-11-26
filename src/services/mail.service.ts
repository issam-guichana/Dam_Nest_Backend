import * as nodemailer from 'nodemailer';
import { Injectable } from '@nestjs/common';
import * as otpGenerator from 'otp-generator';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false,
      auth: {
        user: 'tmohamedali198@gmail.com',
        pass: 'ojyw unjd wicx zrqk',
      },
      logger: true,
      debugger: true,
    });
  }

  async sendPasswordResetEmail(to: string, otp: string) {
    const mailOptions = {
      from: 'service security',
      to: to,
      subject: 'Password Reset Request',
      html: `<p>Your OTP for password reset is:</p><h1>${otp}</h1>`,
      headers: {
        'Content-Type': 'text/html; charset=UTF-8',
      },
    };

    await this.transporter.sendMail(mailOptions);
    return otp;
  }
}