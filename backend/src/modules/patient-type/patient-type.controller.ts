import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Put,
  Delete,
  Patch,
} from '@nestjs/common';
import { PatientTypeService } from './patient-type.service';

@Controller('patient-type')
export class PatientTypeController {
  constructor(private readonly service: PatientTypeService) {}

  @Post()
  create(@Body() body: any) {
    return this.service.create(body);
  }

  @Get()
  findAll() {
    return this.service.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.service.findOne(Number(id));
  }

  @Put(':id')
  update(@Param('id') id: string, @Body() body: any) {
    return this.service.update(Number(id), body);
  }

  @Patch(':id/disable')
  disable(@Param('id') id: string) {
    return this.service.disable(Number(id));
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.service.remove(Number(id));
  }
}