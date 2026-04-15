// modules/room/room.module.ts
import { Module } from '@nestjs/common';
import { RoomController } from './room.controller';
import { RoomService } from './room.service';
import { RoomGateway } from './room.gateway';
import { PrismaModule } from '../../shared/prisma/prisma.module';
import { RoomRepository } from './room.repository';

@Module({
  imports: [PrismaModule],
  controllers: [RoomController],
  providers: [
    RoomService,
    RoomGateway, 
    RoomRepository,
  ],
  exports: [
    RoomService,
    RoomGateway,
  ],
})
export class RoomModule {}