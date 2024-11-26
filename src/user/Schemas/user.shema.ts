import { Prop } from '@nestjs/mongoose';
import { Schema, Document } from 'mongoose';

export interface user extends Document {
  
  name: string;
  email: string;
  password: string;
  confirmPassword:string;
  roleId: string;
}

export const UserSchema = new Schema({

  name: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  confirmPassword: { type: String, required: false },
  roleId: { type: String},
});
