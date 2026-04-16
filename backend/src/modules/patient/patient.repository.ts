import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../shared/prisma/prisma.service';
import { CreatePatientDto } from './dto/create-patient.dto';
import { UpdatePatientDto } from './dto/update-patient.dto';

@Injectable()
export class PatientRepository {
  constructor(private readonly prisma: PrismaService) {}

  create(dto: CreatePatientDto) {
    return this.prisma.patient.create({
      data: {
        name: dto.name,
        email: dto.email,
        phone: dto.phone,
        yearOfBirth: dto.yearOfBirth,
        patientType: {
          connect: { id: dto.patientTypeId },
        },
      },
    });
  }

  findAll() {
    return this.prisma.patient.findMany({
      include: {
        patientType: true,
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  findById(id: string) {
    return this.prisma.patient.findUnique({
      where: { id },
      include: {
        patientType: true,
        visits: true,
      },
    });
  }

  update(id: string, dto: UpdatePatientDto) {
    return this.prisma.patient.update({
      where: { id },
      data: {
        ...(dto.name && { name: dto.name }),
        ...(dto.email !== undefined && { email: dto.email }),
        ...(dto.phone && { phone: dto.phone }),
        ...(dto.yearOfBirth && { yearOfBirth: dto.yearOfBirth }),
        ...(dto.patientTypeId && {
          patientType: {
            connect: { id: dto.patientTypeId },
          },
        }),
      },
    });
  }

  delete(id: string) {
    return this.prisma.patient.delete({
      where: { id },
    });
  }

  findByPhone(phone: string) {
    return this.prisma.patient.findUnique({
      where: { phone },
      select: {
        id: true,
        name: true,
        phone: true,
        patientTypeId: true,
      },
    });
  }

  findAgeMatchedPatientTypeRule(age: number) {
    return this.prisma.priorityRule.findFirst({
      where: {
        isActive: true,
        patientTypeId: { not: null },
        patientType: { isActive: true },
        AND: [
          {
            OR: [{ minAge: null }, { minAge: { lte: age } }],
          },
          {
            OR: [{ maxAge: null }, { maxAge: { gte: age } }],
          },
          {
            OR: [{ minAge: { not: null } }, { maxAge: { not: null } }],
          },
        ],
      },
      orderBy: [{ applyOrder: 'asc' }, { priorityValue: 'desc' }],
      select: { patientTypeId: true },
    });
  }

  findDefaultNormalPatientType() {
    return this.prisma.patientType.findFirst({
      where: {
        isActive: true,
        OR: [{ code: 'NORMAL' }, { code: 'normal' }, { name: 'Normal' }, { name: 'normal' }],
      },
      orderBy: { id: 'asc' },
      select: { id: true },
    });
  }
}
