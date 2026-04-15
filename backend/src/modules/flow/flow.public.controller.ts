import {
  Controller,
  Get,
  Param,
  ParseIntPipe,
} from '@nestjs/common';
import { FlowService } from './flow.service';

@Controller('flows')
export class FlowPublicController {
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
}