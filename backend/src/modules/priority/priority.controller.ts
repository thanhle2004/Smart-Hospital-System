import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Put,
  Delete,
  Patch,
  ParseIntPipe,
} from '@nestjs/common';
import { PriorityService } from './priority.service';
import { ZodValidationPipe } from 'src/common/pipes/zod-validation.pipe';
import * as createPriorityRuleDto from './dto/create-priority-rule.dto';
import * as updatePriorityRuleDto from './dto/update-priority-rule.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';
import { Role } from '@prisma/client';
import { UseGuards } from '@nestjs/common';

@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
@Controller('admin/priority-rules')
export class PriorityController {
  constructor(private readonly priorityService: PriorityService) {}

  @Get()
  findAll() {
    return this.priorityService.findAll();
  }
 
  @Get(':id')
  findOne(@Param('id', ParseIntPipe) id: number) {
    return this.priorityService.findOne(id);
  }
 
  @Post()
  create(
    @Body(new ZodValidationPipe(createPriorityRuleDto.createPriorityRuleSchema))
    dto: createPriorityRuleDto.CreatePriorityRuleDto,
  ) {
    return this.priorityService.create(dto);
  }
 
  @Patch(':id')
  update(
    @Param('id', ParseIntPipe) id: number,
    @Body(new ZodValidationPipe(updatePriorityRuleDto.updatePriorityRuleSchema))
    dto: updatePriorityRuleDto.UpdatePriorityRuleDto,
  ) {
    return this.priorityService.update(id, dto);
  }
 
  @Delete(':id')
  remove(@Param('id', ParseIntPipe) id: number) {
    return this.priorityService.remove(id);
  }
 
  @Patch(':id/toggle-active')
  toggleActive(@Param('id', ParseIntPipe) id: number) {
    return this.priorityService.toggleActive(id);
  }
}