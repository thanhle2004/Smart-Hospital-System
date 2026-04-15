import {
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { CreatePatientTypeDto } from './dto/create-patient-type.dto';
import { UpdatePatientTypeDto } from './dto/update-patient-type.dto';
import { PatientTypeRepository } from './patient-type.repository';

@Injectable()
export class PatientTypeService {
  constructor(private readonly repo: PatientTypeRepository) {}
 
  async findAll() {
    return this.repo.findAll();
  }
 
  async findOne(id: number) {
    const patientType = await this.repo.findOne(id);
    if (!patientType) throw new NotFoundException(`PatientType #${id} not found`);
    return patientType;
  }
 
  async create(dto: CreatePatientTypeDto) {
    const existing = await this.repo.findByCode(dto.code);
    if (existing) throw new ConflictException(`Code "${dto.code}" already exists`);
 
    return this.repo.create(dto);
  }
 
  async update(id: number, dto: UpdatePatientTypeDto) {
    await this.findOne(id);
 
    return this.repo.update(id, dto);
  }
 
  async remove(id: number) {
    await this.findOne(id);
 
    const hasPatients = await this.repo.countPatients(id);
    if (hasPatients > 0) {
      throw new ConflictException(
        'Cannot delete: PatientType is in use by existing patients',
      );
    }
 
    return this.repo.delete(id);
  }
 
  async toggleActive(id: number) {
    const patientType = await this.findOne(id);
    return this.repo.toggleActive(id, !patientType.isActive);
  }
}