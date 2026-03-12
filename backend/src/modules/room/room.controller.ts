import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Put,
  Delete,
} from '@nestjs/common';
import { RoomService } from './room.service';

@Controller('room')
export class RoomController {
  constructor(private readonly roomService: RoomService) {}

  @Post()
  create(@Body() body: any) {
    return this.roomService.create(body);
  }

  @Get()
  findAll() {
    return this.roomService.findAll();
  }

  @Get('dashboard')
  getDashboard() {
    return this.roomService.getDashboard();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.roomService.findOne(Number(id));
  }

  @Put(':id')
  update(@Param('id') id: string, @Body() body: any) {
    return this.roomService.update(Number(id), body);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.roomService.remove(Number(id));
  }

  @Get(':id/estimated-waiting-time')
  getEstimatedWaitingTime(@Param('id') id: string) {
    return this.roomService.getEstimatedWaitingTime(Number(id));
  }
}