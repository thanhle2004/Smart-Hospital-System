import { Module } from '@nestjs/common';
import { PatientTypeController } from './patient-type.controller';
import { PatientTypeService } from './patient-type.service';
import { PrismaModule } from '../../shared/prisma/prisma.module';
import { PatientTypeRepository } from './patient-type.repository';

@Module({
  imports: [PrismaModule],
  controllers: [PatientTypeController],
  providers: [PatientTypeService, PatientTypeRepository],
  exports: [PatientTypeService],
})
export class PatientTypeModule {}