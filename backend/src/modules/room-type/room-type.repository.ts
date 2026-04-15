import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../shared/prisma/prisma.service';
import { CreateRoomTypeDto } from './dto/create-room-type.dto';
import { UpdateRoomTypeDto } from './dto/update-room-type.dto';

type DbClient = PrismaService | Prisma.TransactionClient;

@Injectable()
export class RoomTypeRepository {
  constructor(private readonly prisma: PrismaService) {}

  findAll(tx: DbClient = this.prisma) {
    return tx.roomType.findMany({
      include: { _count: { select: { rooms: true } } },
      orderBy: { id: 'asc' },
    });
  }

  findOne(id: number, tx: DbClient = this.prisma) {
    return tx.roomType.findUnique({
      where: { id },
      include: {
        rooms: true,
        _count: { select: { rooms: true, flowRooms: true } },
      },
    });
  }

  create(dto: CreateRoomTypeDto, tx: DbClient = this.prisma) {
    return tx.roomType.create({ data: dto });
  }

  update(id: number, dto: UpdateRoomTypeDto, tx: DbClient = this.prisma) {
    return tx.roomType.update({ where: { id }, data: dto });
  }

  countRooms(id: number, tx: DbClient = this.prisma) {
    return tx.room.count({ where: { roomTypeId: id } });
  }

  countFlowRooms(id: number, tx: DbClient = this.prisma) {
    return tx.flowRoom.count({ where: { roomTypeId: id } });
  }

  delete(id: number, tx: DbClient = this.prisma) {
    return tx.roomType.delete({ where: { id } });
  }
}