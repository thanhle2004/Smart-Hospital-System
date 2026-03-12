import { Module } from '@nestjs/common';
import { VisitController } from './visit.controller';
import { VisitService } from './service/visit.service';
import { QueueService } from './service/queue.service';
import { JsqService } from './service/jsq.service';
import { HrrnService } from './service/hrrn.service';
import { PrismaModule } from '../../prisma/prisma.module';
import { PriorityModule } from '../priority/priority.module';
import { RoomModule } from '../room/room.module';

@Module({
  imports: [PrismaModule, PriorityModule, RoomModule],
  controllers: [VisitController],
  providers: [VisitService, QueueService, JsqService, HrrnService],
})
export class VisitModule {}
