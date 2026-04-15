import { Body, Controller, Get, Param, Patch, Post, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { ZodValidationPipe } from 'src/common/pipes/zod-validation.pipe';
import {
  userIdParamSchema,
  type UserIdParamDto,
} from './dto/user-id-param.dto';
import { createUserSchema, type CreateUserDto } from './dto/create-user.dto';
import { updateUserSchema, type UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';
import { Role } from '@prisma/client';

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get()
  findAll() {
    return this.userService.findAll();
  }

  @Post()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  create(
    @Body(new ZodValidationPipe(createUserSchema))
    dto: CreateUserDto,
  ) {
    return this.userService.create(dto);
  }

  @Patch(':id')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  update(
    @Param(new ZodValidationPipe(userIdParamSchema))
    params: UserIdParamDto,
    @Body(new ZodValidationPipe(updateUserSchema))
    dto: UpdateUserDto,
  ) {
    return this.userService.update(params.id, dto);
  }

  @Get(':id')
  findById(
    @Param(new ZodValidationPipe(userIdParamSchema))
    params: UserIdParamDto,
  ) {
    return this.userService.findById(params.id);
  }

  @Patch(':id/deactivate')
  deactivate(
    @Param(new ZodValidationPipe(userIdParamSchema))
    params: UserIdParamDto,
  ) {
    return this.userService.deactivate(params.id);
  }
}