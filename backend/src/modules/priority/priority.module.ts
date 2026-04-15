import { Module } from '@nestjs/common';
import { PriorityController } from './priority.controller';
import { PriorityService } from './priority.service';
import { PrismaModule } from '../../shared/prisma/prisma.module';
import { PriorityRepository } from './priority.repository';

@Module({
  imports: [PrismaModule],
  controllers: [PriorityController],
  providers: [PriorityService, PriorityRepository],
  exports: [PriorityService],
})
export class PriorityModule {}