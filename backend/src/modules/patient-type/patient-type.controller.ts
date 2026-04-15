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
import { PatientTypeService } from './patient-type.service';
import { ZodValidationPipe } from 'src/common/pipes/zod-validation.pipe';
import * as createPatientTypeDto from './dto/create-patient-type.dto';
import * as updatePatientTypeDto from './dto/update-patient-type.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { Roles } from '../auth/roles.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { Role } from '@prisma/client';

@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('admin/patient-types')
export class PatientTypeController {
  constructor(private readonly patientTypeService: PatientTypeService) {}

  @Get()
  findAll() {
    return this.patientTypeService.findAll();
  }

  @Get(':id')
  findOne(@Param('id', ParseIntPipe) id: number) {
    return this.patientTypeService.findOne(id);
  }

  @Post()
  create(
    @Body(new ZodValidationPipe(createPatientTypeDto.createPatientTypeSchema))
    dto: createPatientTypeDto.CreatePatientTypeDto,
  ) {
    return this.patientTypeService.create(dto);
  }

  @Patch(':id')
  update(
    @Param('id', ParseIntPipe) id: number,
    @Body(new ZodValidationPipe(updatePatientTypeDto.updatePatientTypeSchema))
    dto: updatePatientTypeDto.UpdatePatientTypeDto,
  ) {
    return this.patientTypeService.update(id, dto);
  }

  @Delete(':id')
  remove(@Param('id', ParseIntPipe) id: number) {
    return this.patientTypeService.remove(id);
  }

  @Patch(':id/toggle-active')
  toggleActive(@Param('id', ParseIntPipe) id: number) {
    return this.patientTypeService.toggleActive(id);
  }
}