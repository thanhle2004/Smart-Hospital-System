import { Module } from '@nestjs/common';
import { PatientService } from './patient.service';
import { PatientController } from './patient.controller';
import { PrismaModule } from '../../shared/prisma/prisma.module';
import { PatientRepository } from './patient.repository';

@Module({
  imports: [PrismaModule],
  controllers: [PatientController],
  providers: [PatientService, PatientRepository],
  exports: [PatientService]
})
export class PatientModule {}