import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../shared/prisma/prisma.service';
import { CreatePriorityRuleDto } from './dto/create-priority-rule.dto';
import { UpdatePriorityRuleDto } from './dto/update-priority-rule.dto';

const priorityRuleInclude = {
  patientType: { select: { id: true, name: true, code: true } },
} as const;

type DbClient = PrismaService | Prisma.TransactionClient;

@Injectable()
export class PriorityRepository {
  constructor(private readonly prisma: PrismaService) {}

  findAll(tx: DbClient = this.prisma) {
    return tx.priorityRule.findMany({
      include: priorityRuleInclude,
      orderBy: [{ applyOrder: 'asc' }, { priorityValue: 'desc' }],
    });
  }

  findOne(id: number, tx: DbClient = this.prisma) {
    return tx.priorityRule.findUnique({
      where: { id },
      include: priorityRuleInclude,
    });
  }

  create(dto: CreatePriorityRuleDto, tx: DbClient = this.prisma) {
    return tx.priorityRule.create({ data: dto });
  }

  update(id: number, dto: UpdatePriorityRuleDto, tx: DbClient = this.prisma) {
    return tx.priorityRule.update({ where: { id }, data: dto });
  }

  delete(id: number, tx: DbClient = this.prisma) {
    return tx.priorityRule.delete({ where: { id } });
  }

  toggleActive(id: number, isActive: boolean, tx: DbClient = this.prisma) {
    return tx.priorityRule.update({
      where: { id },
      data: { isActive },
    });
  }

  findPatientType(patientTypeId: number, tx: DbClient = this.prisma) {
    return tx.patientType.findUnique({ where: { id: patientTypeId } });
  }

  findActiveRules(tx: DbClient = this.prisma) {
    return tx.priorityRule.findMany({
      where: { isActive: true },
      orderBy: { applyOrder: 'asc' },
    });
  }
}