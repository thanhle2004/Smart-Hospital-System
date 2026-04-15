import { Module } from '@nestjs/common';
import { FlowController } from './flow.controller';
import { FlowPublicController } from './flow.public.controller';
import { FlowService } from './flow.service';
import { PrismaModule } from '../../shared/prisma/prisma.module';
import { FlowRepository } from './flow.repository';

@Module({
  imports: [PrismaModule],
  controllers: [FlowController, FlowPublicController],
  providers: [FlowService, FlowRepository],
  exports: [FlowService],
})
export class FlowModule {}