import { Module } from '@nestjs/common';
import { VisitController } from './visit.controller';
import { VisitService } from './visit.service';

import { PrismaModule } from '../../shared/prisma/prisma.module';
import { PriorityModule } from '../priority/priority.module';
import { RoomModule } from '../room/room.module';
import { VisitFlowModule } from '../visit-flow/visit-flow.module';
import { VisitRepository } from './visit.repository';

@Module({
  imports: [
    PrismaModule,
    PriorityModule,
    RoomModule,
    VisitFlowModule,
  ],
  controllers: [VisitController],
  providers: [VisitService, VisitRepository],
})
export class VisitModule {}