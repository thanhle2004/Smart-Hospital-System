import { Controller, Get, Param, Patch } from '@nestjs/common';
import { UserService } from './user.service';

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get()
  findAll() {
    return this.userService.findAll();
  }

  @Get(':id')
  findById(@Param('id') id: string) {
    return this.userService.findById(id);
  }

  @Patch(':id/deactivate')
  deactivate(@Param('id') id: string) {
    return this.userService.deactivate(id);
  }
}