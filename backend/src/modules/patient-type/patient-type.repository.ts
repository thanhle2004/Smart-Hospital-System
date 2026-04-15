import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../shared/prisma/prisma.service';
import { CreatePatientTypeDto } from './dto/create-patient-type.dto';
import { UpdatePatientTypeDto } from './dto/update-patient-type.dto';

type DbClient = PrismaService | Prisma.TransactionClient;

@Injectable()
export class PatientTypeRepository {
  constructor(private readonly prisma: PrismaService) {}

  findAll(tx: DbClient = this.prisma) {
    return tx.patientType.findMany({
      orderBy: { id: 'asc' },
    });
  }

  findOne(id: number, tx: DbClient = this.prisma) {
    return tx.patientType.findUnique({ where: { id } });
  }

  findByCode(code: string, tx: DbClient = this.prisma) {
    return tx.patientType.findUnique({ where: { code } });
  }

  create(dto: CreatePatientTypeDto, tx: DbClient = this.prisma) {
    return tx.patientType.create({ data: dto });
  }

  update(id: number, dto: UpdatePatientTypeDto, tx: DbClient = this.prisma) {
    return tx.patientType.update({ where: { id }, data: dto });
  }

  delete(id: number, tx: DbClient = this.prisma) {
    return tx.patientType.delete({ where: { id } });
  }

  countPatients(id: number, tx: DbClient = this.prisma) {
    return tx.patient.count({ where: { patientTypeId: id } });
  }

  toggleActive(id: number, isActive: boolean, tx: DbClient = this.prisma) {
    return tx.patientType.update({
      where: { id },
      data: { isActive },
    });
  }
}