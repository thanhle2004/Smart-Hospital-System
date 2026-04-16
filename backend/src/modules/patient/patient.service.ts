import {
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { PatientRepository } from './patient.repository';
import { CreatePatientDto } from './dto/create-patient.dto';
import { UpdatePatientDto } from './dto/update-patient.dto';
import { createHmac, timingSafeEqual } from 'crypto';

@Injectable()
export class PatientService {
  constructor(private readonly repo: PatientRepository) {}

  private calculateAge(yearOfBirth: number) {
    return new Date().getFullYear() - yearOfBirth;
  }

  private async resolvePatientTypeIdForCreate(dto: CreatePatientDto) {
    if (dto.patientTypeId) {
      return dto.patientTypeId;
    }

    const age = this.calculateAge(dto.yearOfBirth);
    const ageMatchedRule = await this.repo.findAgeMatchedPatientTypeRule(age);
    if (ageMatchedRule?.patientTypeId) {
      return ageMatchedRule.patientTypeId;
    }

    const normalType = await this.repo.findDefaultNormalPatientType();
    if (normalType?.id) {
      return normalType.id;
    }

    throw new BadRequestException('Default patient type NORMAL is not configured or inactive');
  }

  private getPatientSessionSecret() {
    return process.env.PATIENT_SESSION_SECRET || process.env.JWT_ACCESS_SECRET || 'dev-patient-session-secret';
  }

  buildPatientSessionToken(patientId: string) {
    const signature = createHmac('sha256', this.getPatientSessionSecret())
      .update(patientId)
      .digest('hex');
    return `${patientId}.${signature}`;
  }

  resolvePatientIdFromSessionToken(token?: string | null) {
    if (!token) return null;

    const lastDot = token.lastIndexOf('.');
    if (lastDot <= 0 || lastDot === token.length - 1) return null;

    const patientId = token.slice(0, lastDot);
    const expected = this.buildPatientSessionToken(patientId);

    const expectedBuf = Buffer.from(expected);
    const providedBuf = Buffer.from(token);
    if (expectedBuf.length !== providedBuf.length) return null;

    return timingSafeEqual(expectedBuf, providedBuf) ? patientId : null;
  }

  async create(dto: CreatePatientDto) {
    try {
      const patientTypeId = await this.resolvePatientTypeIdForCreate(dto);
      return await this.repo.create({ ...dto, patientTypeId });
    } catch (error: any) {
      if (error.code === 'P2002') {
        throw new ConflictException('Email or phone already exists');
      }
      throw error;
    }
  }

  async findAll() {
    return this.repo.findAll();
  }

  async findOne(id: string) {
    const patient = await this.repo.findById(id);

    if (!patient) {
      throw new NotFoundException('Patient not found');
    }

    return patient;
  }

  async update(id: string, dto: UpdatePatientDto) {
    await this.findOne(id);

    try {
      return await this.repo.update(id, dto);
    } catch (error: any) {
      if (error.code === 'P2002') {
        throw new ConflictException('Email or phone already exists');
      }
      throw error;
    }
  }

  async remove(id: string) {
    await this.findOne(id);
    return this.repo.delete(id);
  }

  async checkPhone(phone: string) {
    const patient = await this.repo.findByPhone(phone);

    return {
      exists: !!patient,
      patient: patient ?? null,
    };
  }
}