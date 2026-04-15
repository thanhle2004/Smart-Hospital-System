import { Module } from '@nestjs/common';
import { VisitFlowService } from './visit-flow.service';
import { VisitFlowController } from './visit-flow.controller';
import { PrismaModule } from '../../shared/prisma/prisma.module';
import { VisitFlowRepository } from './visit-flow.repository';

@Module({
  imports: [PrismaModule],
  controllers: [VisitFlowController],
  providers: [VisitFlowService, VisitFlowRepository],
  exports: [VisitFlowService],
})
export class VisitFlowModule {}