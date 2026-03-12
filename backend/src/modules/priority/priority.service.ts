import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { PriorityRule } from '@prisma/client';

@Injectable()
export class PriorityService {
  constructor(private prisma: PrismaService) {}

  async create(data: {
    ruleName: string;
    minAge?: number;
    maxAge?: number;
    patientTypeId?: number;
    isEmergency?: boolean;
    priorityValue: number;
    applyOrder?: number;
  }) {
    return this.prisma.priorityRule.create({
      data,
    });
  }

  async findAll() {
    return this.prisma.priorityRule.findMany({
      where: { isActive: true },
      orderBy: { applyOrder: 'asc' },
    });
  }

  async findOne(id: number) {
    return this.prisma.priorityRule.findUnique({
      where: { id },
    });
  }

  async update(id: number, data: Partial<PriorityRule>) {
    return this.prisma.priorityRule.update({
      where: { id },
      data,
    });
  }

  async remove(id: number) {
    return this.prisma.priorityRule.update({
      where: { id },
      data: { isActive: false },
    });
  }

  async applyPriority(params: {
    age?: number;
    patientTypeId?: number;
    isEmergency?: boolean;
  }) {
    const { age, patientTypeId, isEmergency } = params;

    const rules = await this.prisma.priorityRule.findMany({
      where: { isActive: true },
      orderBy: { applyOrder: 'asc' },
    });

    for (const rule of rules) {
      // Emergency check
      if (rule.isEmergency && isEmergency) {
        return rule;
      }

      // Patient type check
      if (
        rule.patientTypeId &&
        rule.patientTypeId === patientTypeId
      ) {
        return rule;
      }

      // Age check
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