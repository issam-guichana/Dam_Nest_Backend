import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';

export type ResetTokenDocument = ResetToken & Document;
@Schema({ versionKey: false, timestamps: true })
export class ResetToken extends Document {
  @Prop({ required: true })
  token: string;
  @Prop({ required: true, type: mongoose.Types.ObjectId })
  userId: mongoose.Types.ObjectId;
  @Prop({ required: true })
  expiryDate: Date;
  @Prop({ required: true })
  otp: string;
}

export const ResetTokenSchema = SchemaFactory.createForClass(ResetToken);
