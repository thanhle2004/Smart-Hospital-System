import { Module } from '@nestjs/common';
import { RoomTypeService } from './room-type.service';
import { RoomTypeController } from './room-type.controller';
import { RoomTypePublicController } from './room-type.public.controller';
import { PrismaModule } from '../../shared/prisma/prisma.module';
import { RoomTypeRepository } from './room-type.repository';

@Module({
  imports: [PrismaModule],
  controllers: [RoomTypeController, RoomTypePublicController],
  providers: [RoomTypeService, RoomTypeRepository],
  exports: [RoomTypeService],
})
export class RoomTypeModule {}