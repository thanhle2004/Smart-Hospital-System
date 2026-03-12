import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Put,
  Delete,
} from '@nestjs/common';
import { PriorityService } from './priority.service';

@Controller('priority')
export class PriorityController {
  constructor(private readonly priorityService: PriorityService) {}

  @Post()
  create(@Body() body: any) {
    return this.priorityService.create(body);
  }

  @Get()
  findAll() {
    return this.priorityService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.priorityService.findOne(Number(id));
  }

  @Put(':id')
  update(@Param('id') id: string, @Body() body: any) {
    return this.priorityService.update(Number(id), body);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.priorityService.remove(Number(id));
  }
}