import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { userResponseSchema } from './dto/user-response.dto';
import type { CreateUserDto } from './dto/create-user.dto';
import type { UpdateUserDto } from './dto/update-user.dto';
import { HashService } from 'src/shared/services/hash.service';
import { UserRepository } from './user.repository';

@Injectable()
export class UserService {
  constructor(
    private readonly repo: UserRepository,
    private readonly hashService: HashService,
  ) {}

  async create(dto: CreateUserDto) {
    try {
      const passwordHash = await this.hashService.hash(dto.password);

      const user = await this.repo.create(dto, passwordHash);

      return userResponseSchema.parse(user);
    } catch (error: any) {
      if (error.code === 'P2002') {
        throw new ConflictException('Email already exists');
      }

      throw error;
    }
  }

  async findAll() {
    const users = await this.repo.findAll();
    return users.map((user) => userResponseSchema.parse(user));
  }

  async update(id: string, dto: UpdateUserDto) {
    await this.findById(id);

    try {
      const user = await this.repo.update(id, dto);

      return userResponseSchema.parse(user);
    } catch (error: any) {
      if (error.code === 'P2002') {
        throw new ConflictException('Email already exists');
      }

      throw error;
    }
  }

  async findById(id: string) {
    const user = await this.repo.findById(id);

    if (!user) {
      throw new NotFoundException(`User ${id} not found`);
    }

    return userResponseSchema.parse(user);
  }

  async deactivate(id: string) {
    await this.findById(id);

    const user = await this.repo.deactivate(id);

    return userResponseSchema.parse(user);
  }
}