import { Module } from '@nestjs/common';
import { PatientTypeController } from './patient-type.controller';
import { PatientTypeService } from './patient-type.service';
import { PrismaModule } from '../../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [PatientTypeController],
  providers: [PatientTypeService],
  exports: [PatientTypeService],
})
export class PatientTypeModule {}