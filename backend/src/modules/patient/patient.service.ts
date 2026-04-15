import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { PatientRepository } from './patient.repository';
import { CreatePatientDto } from './dto/create-patient.dto';
import { UpdatePatientDto } from './dto/update-patient.dto';
import { createHmac, timingSafeEqual } from 'crypto';

@Injectable()
export class PatientService {
  constructor(private readonly repo: PatientRepository) {}

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
      return await this.repo.create(dto);
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