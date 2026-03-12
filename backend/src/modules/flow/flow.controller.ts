import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Delete,
} from '@nestjs/common';
import { FlowService } from './flow.service';

@Controller('flow')
export class FlowController {
  constructor(private readonly flowService: FlowService) {}

  @Post()
  create(@Body('name') name: string) {
    return this.flowService.createFlow(name);
  }

  @Get()
  findAll() {
    return this.flowService.findAllFlows();
  }

  @Get('simple')
  findSimple() {
    return this.flowService.findSimpleFlows();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.flowService.findOneFlow(Number(id));
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.flowService.deleteFlow(Number(id));
  }

  @Post(':id/rooms')
  addRoom(
    @Param('id') id: string,
    @Body() body: { roomId: number; defaultOrder: number },
  ) {
    return this.flowService.addRoomTypeToFlow(
      Number(id),
      body.roomId,
      body.defaultOrder,
    );
  }

  @Delete(':id/rooms/:roomId')
  removeRoom(
    @Param('id') id: string,
    @Param('roomId') roomId: string,
  ) {
    return this.flowService.removeRoomTypeFromFlow(
      Number(id),
      Number(roomId),
    );
  }

  @Post(':id/dependencies')
  addDependency(
    @Param('id') id: string,
    @Body() body: { roomId: number; requiredRoomId: number },
  ) {
    return this.flowService.addDependency(
      Number(id),
      body.roomId,
      body.requiredRoomId,
    );
  }

  @Delete(':id/dependencies')
  removeDependency(
    @Param('id') id: string,
    @Body() body: { roomId: number; requiredRoomId: number },
  ) {
    return this.flowService.removeDependency(
      Number(id),
      body.roomId,
      body.requiredRoomId,
    );
  }
}