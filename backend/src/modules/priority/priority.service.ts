import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, PriorityRule } from '@prisma/client';
import { CreatePriorityRuleDto } from './dto/create-priority-rule.dto';
import { UpdatePriorityRuleDto } from './dto/update-priority-rule.dto';
import { PriorityRepository } from './priority.repository';

@Injectable()
export class PriorityService {
  constructor(private readonly repo: PriorityRepository) {}

  async findAll() {
    return this.repo.findAll();
  }
 
  async findOne(id: number) {
    const rule = await this.repo.findOne(id);
    if (!rule) throw new NotFoundException(`PriorityRule #${id} not found`);
    return rule;
  }

  async create(dto: CreatePriorityRuleDto) {
    this.validateAgeRange(dto.minAge, dto.maxAge);
 
    if (dto.patientTypeId) {
      await this.assertPatientTypeExists(dto.patientTypeId);
    }
 
    return this.repo.create(dto);
  }
 
  async update(id: number, dto: UpdatePriorityRuleDto) {
    const rule = await this.findOne(id);
 
    const minAge = dto.minAge ?? rule.minAge ?? undefined;
    const maxAge = dto.maxAge ?? rule.maxAge ?? undefined;
    this.validateAgeRange(minAge, maxAge);
 
    if (dto.patientTypeId) {
      await this.assertPatientTypeExists(dto.patientTypeId);
    }
 
    return this.repo.update(id, dto);
  }
 
  async remove(id: number) {
    await this.findOne(id);
    return this.repo.delete(id);
  }
 
  async toggleActive(id: number) {
    const rule = await this.findOne(id);
    return this.repo.toggleActive(id, !rule.isActive);
  }

  private validateAgeRange(minAge?: number, maxAge?: number) {
    if (minAge !== undefined && maxAge !== undefined && minAge > maxAge) {
      throw new BadRequestException('minAge must be less than or equal to maxAge');
    }
  }
 
  private async assertPatientTypeExists(patientTypeId: number) {
    const pt = await this.repo.findPatientType(patientTypeId);
    if (!pt) throw new NotFoundException(`PatientType #${patientTypeId} not found`);
  }

  async applyPriority(
    params: {
      age?: number;
      patientTypeId?: number;
      isEmergency?: boolean;
    },
    tx?: Prisma.TransactionClient,
  ) {
    const { age, patientTypeId, isEmergency } = params;

    const rules = await this.repo.findActiveRules(tx);

    for (const rule of rules) {
      ////////////////////////////////////////////////
      // EMERGENCY CHECK
      ////////////////////////////////////////////////
      if (rule.isEmergency !== null) {
        if (rule.isEmergency === isEmergency) {
          return rule;
        }
        continue;
      }

      ////////////////////////////////////////////////
      // PATIENT TYPE CHECK
      ////////////////////////////////////////////////
      if (rule.patientTypeId !== null) {
        if (rule.patientTypeId === patientTypeId) {
          return rule;
        }
        continue;
      }

      ////////////////////////////////////////////////
      // AGE CHECK
      ////////////////////////////////////////////////
      if (
        rule.minAge !== null &&
        rule.maxAge !== null &&
        age !== undefined &&
        age >= rule.minAge &&
        age <= rule.maxAge
      ) {
        return rule;
      }
    }

    return null;
  }
}