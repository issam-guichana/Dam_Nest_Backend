import { Injectable, BadRequestException, InternalServerErrorException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { user } from 'src/user/Schemas/user.shema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import * as mongoose from 'mongoose';

@Injectable()
export class UserService {
  constructor(@InjectModel('user') private userModel: Model<user>) {}

  async create(createUserDto: CreateUserDto): Promise<any> {
    const { email, password, confirmPassword, name } = createUserDto;

    // Validation des champs requis
    if (!email || !password || !name || !confirmPassword) {
      throw new BadRequestException('All fields are required');
    }

    // Vérification que les mots de passe correspondent
    if (password !== confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    // Vérifier si l'email est déjà utilisé
    const emailInUse = await this.userModel.findOne({ email }).lean();
    if (emailInUse) {
      throw new BadRequestException('Email already in use');
    }

    // Hachage du mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);

    // Remplacez par l'ID réel de votre rôle par défaut
    const defaultRoleId = new mongoose.Types.ObjectId("609d1e90fdb3a2421cfa7d55"); // Exemple d'ID ObjectId

    try {
      // Création d'un nouvel utilisateur
      const newUser = await this.userModel.create({
        name,
        email,
        password: hashedPassword,
        roleId: defaultRoleId, // Assurez-vous que cela correspond à un rôle valide dans votre base de données
      });

      return {
        message: 'User registered successfully',
        userId: newUser._id.toString(),
      };
    } catch (error) {
      console.error('Error creating user:', error);
      // Gérer les erreurs de validation
      if (error instanceof mongoose.Error.ValidationError) {
        throw new BadRequestException(error.message);
      }
      // Gérer les autres erreurs internes
      throw new InternalServerErrorException('Failed to signup user');
    }
  }

  async findAll(): Promise<user[]> {
    return this.userModel.find().exec();
  }

  async findOne(id: string): Promise<user> {
    return this.userModel.findById(id).exec();
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<user> {
    return this.userModel.findByIdAndUpdate(id, updateUserDto, { new: true }).exec();
  }

  async remove(id: string): Promise<user> {
    return this.userModel.findByIdAndDelete(id).exec();
  }
}
