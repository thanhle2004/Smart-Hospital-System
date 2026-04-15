import {
  Controller,
  Get,
  Param,
  ParseIntPipe,
} from '@nestjs/common';
import { RoomTypeService } from './room-type.service';

@Controller('room-types')
export class RoomTypePublicController {
  constructor(private readonly roomTypeService: RoomTypeService) {}

  @Get()
  findAll() {
    return this.roomTypeService.findAll();
  }

  @Get(':id')
  findOne(@Param('id', ParseIntPipe) id: number) {
    return this.roomTypeService.findOne(id);
  }
}
