import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
  ParseIntPipe,
  UseGuards,
} from '@nestjs/common';
import { RoomTypeService } from './room-type.service';
import { ZodValidationPipe } from 'src/common/pipes/zod-validation.pipe';
import * as createRoomTypeDto from './dto/create-room-type.dto';
import * as updateRoomTypeDto from './dto/update-room-type.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';
import { Role } from '@prisma/client';

@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('admin/room-types')
export class RoomTypeController {
  constructor(private readonly roomTypeService: RoomTypeService) {}

  @Get()
  findAll() {
    return this.roomTypeService.findAll();
  }

  @Get(':id')
  findOne(@Param('id', ParseIntPipe) id: number) {
    return this.roomTypeService.findOne(id);
  }

  @Post()
  create(
    @Body(new ZodValidationPipe(createRoomTypeDto.createRoomTypeSchema))
    dto: createRoomTypeDto.CreateRoomTypeDto,
  ) {
    return this.roomTypeService.create(dto);
  }

  @Patch(':id')
  update(
    @Param('id', ParseIntPipe) id: number,
    @Body(new ZodValidationPipe(updateRoomTypeDto.updateRoomTypeSchema))
    dto: updateRoomTypeDto.UpdateRoomTypeDto,
  ) {
    return this.roomTypeService.update(id, dto);
  }

  @Delete(':id')
  remove(@Param('id', ParseIntPipe) id: number) {
    return this.roomTypeService.remove(id);
  }
}