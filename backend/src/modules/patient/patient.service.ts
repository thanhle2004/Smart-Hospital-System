import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class PatientService {
  constructor(private prisma: PrismaService) {}

  async create(data: {
    name: string;
    email?: string;
    phone: string;
    patientTypeId: number;
  }) {
    try {
      return await this.prisma.patient.create({
        data,
      });
    } catch (error) {
      if (error.code === 'P2002') {
        throw new ConflictException('Email or phone already exists');
      }
      throw error;
    }
  }

  async findAll() {
    return this.prisma.patient.findMany({
      include: {
        patientType: true,
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findOne(id: number) {
    const patient = await this.prisma.patient.findUnique({
      where: { id },
      include: {
        patientType: true,
        visits: true,
      },
    });

    if (!patient) {
      throw new NotFoundException('Patient not found');
    }

    return patient;
  }

  async update(
    id: number,
    data: {
      name?: string;
      email?: string;
      phone?: string;
      patientTypeId?: number;
    },
  ) {
    await this.findOne(id);

    try {
      return await this.prisma.patient.update({
        where: { id },
        data,
      });
    } catch (error) {
      if (error.code === 'P2002') {
        throw new ConflictException('Email or phone already exists');
      }
      throw error;
    }
  }

  async remove(id: number) {
    await this.findOne(id);

    return this.prisma.patient.delete({
      where: { id },
    });
  }

  async checkPhone(phone: string) {
    const patient = await this.prisma.patient.findUnique({
      where: { phone },
      select: {
        id: true,
        name: true,
        phone: true,
        patientTypeId: true,
      },
    });

    return {
      exists: !!patient,
      patient: patient ?? null,
    };
  }
}