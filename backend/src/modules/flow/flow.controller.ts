import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  ParseIntPipe,
  UseGuards,
} from '@nestjs/common';
import { FlowService } from './flow.service';
import { ZodValidationPipe } from 'src/common/pipes/zod-validation.pipe';
import * as createFlowDto from './dto/create-flow.dto';
import * as updateFlowDto from './dto/update-flow.dto';
import * as upsertFlowRoomsDto from './dto/upsert-flow-rooms.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';
import { Role } from '@prisma/client';

@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('admin/flows')
export class FlowController {
  constructor(private readonly flowService: FlowService) {}

  // GET all flows (detailed)
  @Get()
  findAll() {
    return this.flowService.findAll();
  }

  // GET all flows (name only, for dropdowns)
  @Get('simple')
  findAllSimple() {
    return this.flowService.findAllSimple();
  }

  // GET flow by ID (detailed)
  @Get(':id')
  findOne(@Param('id', ParseIntPipe) id: number) {
    return this.flowService.findOne(id);
  }

  // POST create new flow
  @Post()
  create(
    @Body(new ZodValidationPipe(createFlowDto.createFlowSchema))
    dto: createFlowDto.CreateFlowDto,
  ) {
    return this.flowService.create(dto);
  }

  // PATCH update flow details (currently only name can be updated)
  @Patch(':id')
  update(
    @Param('id', ParseIntPipe) id: number,
    @Body(new ZodValidationPipe(updateFlowDto.updateFlowSchema))
    dto: updateFlowDto.UpdateFlowDto,
  ) {
    return this.flowService.update(id, dto);
  }

  @Delete(':id')
  remove(@Param('id', ParseIntPipe) id: number) {
    return this.flowService.remove(id);
  }

  //UPDATE flow rooms & dependencies in bulk
  @Patch(':id/rooms')
  upsertRooms(
    @Param('id', ParseIntPipe) id: number,
    @Body(new ZodValidationPipe(upsertFlowRoomsDto.upsertFlowRoomsSchema))
    dto: upsertFlowRoomsDto.UpsertFlowRoomsDto,
  ) {
    return this.flowService.upsertRooms(id, dto);
  }

  // POST add a single room to the flow
  @Post(':id/rooms')
  addRoom(
    @Param('id', ParseIntPipe) id: number,
    @Body(new ZodValidationPipe(createFlowDto.flowRoomItemSchema))
    dto: createFlowDto.FlowRoomItemDto,
  ) {
    return this.flowService.addRoom(id, dto);
  }

  // DELETE remove a single room from the flow
  @Delete(':id/rooms/:roomTypeId')
  removeRoom(
    @Param('id', ParseIntPipe) id: number,
    @Param('roomTypeId', ParseIntPipe) roomTypeId: number,
  ) {
    return this.flowService.removeRoom(id, roomTypeId);
  }

  // POST add a dependency between rooms in the flow
  @Post(':id/dependencies')
  addDependency(
    @Param('id', ParseIntPipe) id: number,
    @Body(new ZodValidationPipe(createFlowDto.flowRoomDependencyItemSchema))
    dto: createFlowDto.FlowRoomDependencyItemDto,
  ) {
    return this.flowService.addDependency(id, dto);
  }

  // DELETE remove a dependency between rooms in the flow
  @Delete(':id/dependencies')
  removeDependency(
    @Param('id', ParseIntPipe) id: number,
    @Body(new ZodValidationPipe(createFlowDto.flowRoomDependencyItemSchema))
    dto: createFlowDto.FlowRoomDependencyItemDto,
  ) {
    return this.flowService.removeDependency(id, dto);
  }
}