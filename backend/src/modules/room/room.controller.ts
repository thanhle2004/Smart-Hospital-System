// modules/room/room.controller.ts
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { CurrentUser } from '../auth/current-user.decorator';
import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Put,
  Delete,
  UseGuards,
  ParseIntPipe,
} from '@nestjs/common';
import { RoomService } from './room.service';
import { ZodValidationPipe } from 'src/common/pipes/zod-validation.pipe';
import * as createRoomDto from './dto/create-room.dto';
import * as updateRoomDto from './dto/update-room.dto';

@Controller('room')
export class RoomController {
  constructor(private readonly roomService: RoomService) {}

  // ─── Static routes first - avoid being matched by ':id' ──────────────────

  @Get('dashboard')
  getDashboard() {
    return this.roomService.getDashboard();
  }

  @Get('active')
  getActive() {
    return this.roomService.getActiveRooms();
  }

  @Get('stats') 
  getStats() {
    return this.roomService.getDoctorStats();
  }

  @Get('admin-dashboard')
  getAdminDashboard() {
    return this.roomService.getAdminDashboard();
  }

  @Get('current-assignment')
  @UseGuards(JwtAuthGuard)
  getCurrentAssignment(@CurrentUser() user: { userId: string }) {
    return this.roomService.getCurrentAssignment(user.userId);
  }

  // ─── CRUD ─────────────────────────────────────────────────────────────────

  @Post()
  create(
    @Body(new ZodValidationPipe(createRoomDto.createRoomSchema))
    body: createRoomDto.CreateRoomDto,
  ) {
    return this.roomService.create(body);
  }

  @Get()
  findAll() {
    return this.roomService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.roomService.findOne(Number(id));
  }

  @Put(':id')
  update(
    @Param('id') id: string,
    @Body(new ZodValidationPipe(updateRoomDto.updateRoomSchema))
    body: updateRoomDto.UpdateRoomDto,
  ) {
    return this.roomService.update(Number(id), body);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.roomService.remove(Number(id));
  }

  // ─── Room-specific endpoints ──────────────────────────────────────────────

  @Get(':id/estimated-waiting-time')
  getEstimatedWaitingTime(@Param('id') id: string) {
    return this.roomService.getEstimatedWaitingTime(Number(id));
  }

  @Get(':id/doctors')
  getDoctors(@Param('id', ParseIntPipe) id: number) {
    return this.roomService.getActiveDoctors(id);
  }

  @Get(':id/queue')
  getQueue(@Param('id', ParseIntPipe) id: number) {
    return this.roomService.getQueue(id);
  }

  // ─── Check-in / Check-out (auth required) ────────────────────────────────

  @Post(':id/check-in')
  @UseGuards(JwtAuthGuard)
  checkIn(
    @Param('id', ParseIntPipe) id: number,
    @CurrentUser() user: { userId: string },
  ) {
    return this.roomService.checkIn(id, user.userId);
  }

  @Post(':id/check-out')
  @UseGuards(JwtAuthGuard)
  checkOut(
    @Param('id', ParseIntPipe) id: number,
    @CurrentUser() user: { userId: string },
  ) {
    return this.roomService.checkOut(id, user.userId);
  }
}