import {
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class PatientTypeService {
  constructor(private prisma: PrismaService) {}

  async create(data: {
    code: string;
    name: string;
    description?: string;
    basePriority?: number;
  }) {
    try {
      return await this.prisma.patientType.create({
        data,
      });
    } catch (error) {
      if (error.code === 'P2002') {
        throw new ConflictException('PatientType code already exists');
      }
      throw error;
    }
  }

  async findAll() {
    return this.prisma.patientType.findMany({
      orderBy: { id: 'asc' },
    });
  }

  async findOne(id: number) {
    const type = await this.prisma.patientType.findUnique({
      where: { id },
      include: {
        patients: true,
        priorityRules: true,
      },
    });

    if (!type) {
      throw new NotFoundException('PatientType not found');
    }

    return type;
  }

  async update(
    id: number,
    data: {
      code?: string;
      name?: string;
      description?: string;
      basePriority?: number;
      isActive?: boolean;
    },
  ) {
    await this.findOne(id);

    try {
      return await this.prisma.patientType.update({
        where: { id },
        data,
      });
    } catch (error) {
      if (error.code === 'P2002') {
        throw new ConflictException('PatientType code already exists');
      }
      throw error;
    }
  }

  async remove(id: number) {
    const type = await this.prisma.patientType.findUnique({
      where: { id },
      include: { patients: true },
    });

    if (!type) {
      throw new NotFoundException('PatientType not found');
    }

    if (type.patients.length > 0) {
      throw new BadRequestException(
        'Cannot delete PatientType because patients are using it',
      );
    }

    return this.prisma.patientType.delete({
      where: { id },
    });
  }

  async disable(id: number) {
    await this.findOne(id);

    return this.prisma.patientType.update({
      where: { id },
      data: { isActive: false },
    });
  }
}