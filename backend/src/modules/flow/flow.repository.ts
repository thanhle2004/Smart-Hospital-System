import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../shared/prisma/prisma.service';
import { CreateFlowDto, FlowRoomDependencyItemDto, FlowRoomItemDto } from './dto/create-flow.dto';
import { UpdateFlowDto } from './dto/update-flow.dto';

const FLOW_FULL_INCLUDE = {
  flowRooms: {
    include: { roomType: true },
    orderBy: { defaultOrder: 'asc' as const },
  },
  dependencies: {
    include: {
      roomType: { select: { id: true, name: true } },
      requiredRoomType: { select: { id: true, name: true } },
    },
  },
  _count: { select: { visits: true } },
} as const;

type DbClient = PrismaService | Prisma.TransactionClient;

@Injectable()
export class FlowRepository {
  constructor(private readonly prisma: PrismaService) {}

  findAll(tx: DbClient = this.prisma) {
    return tx.flow.findMany({
      include: FLOW_FULL_INCLUDE,
      orderBy: { id: 'asc' },
    });
  }

  findAllSimple(tx: DbClient = this.prisma) {
    return tx.flow.findMany({
      select: { id: true, name: true },
      orderBy: { name: 'asc' },
    });
  }

  findOne(id: number, tx: DbClient = this.prisma) {
    return tx.flow.findUnique({
      where: { id },
      include: FLOW_FULL_INCLUDE,
    });
  }

  create(dto: CreateFlowDto, tx: DbClient = this.prisma) {
    return tx.flow.create({
      data: {
        name: dto.name,
        flowRooms: {
          create: dto.rooms.map((r) => ({
            roomTypeId: r.roomTypeId,
            defaultOrder: r.defaultOrder,
          })),
        },
        ...(dto.dependencies?.length && {
          dependencies: {
            create: dto.dependencies.map((d) => ({
              roomTypeId: d.roomTypeId,
              requiredRoomTypeId: d.requiredRoomTypeId,
            })),
          },
        }),
      },
      include: FLOW_FULL_INCLUDE,
    });
  }

  update(id: number, dto: UpdateFlowDto, tx: DbClient = this.prisma) {
    return tx.flow.update({
      where: { id },
      data: dto,
      include: FLOW_FULL_INCLUDE,
    });
  }

  async delete(id: number, tx: DbClient = this.prisma) {
    // Delete dependent records first (cascading delete)
    await tx.flowRoomDependency.deleteMany({ where: { flowId: id } });
    await tx.flowRoom.deleteMany({ where: { flowId: id } });
    
    // Then delete the flow itself
    return tx.flow.delete({ where: { id } });
  }

  countActiveVisits(id: number, tx: DbClient = this.prisma) {
    return tx.visit.count({
      where: { flowId: id, status: { in: ['WAITING', 'IN_PROGRESS'] } },
    });
  }

  findRoomType(id: number, tx: DbClient = this.prisma) {
    return tx.roomType.findUnique({ where: { id } });
  }

  findRoomTypes(roomTypeIds: number[], tx: DbClient = this.prisma) {
    return tx.roomType.findMany({
      where: { id: { in: roomTypeIds } },
      select: { id: true },
    });
  }

  createFlowRoom(flowId: number, dto: FlowRoomItemDto, tx: DbClient = this.prisma) {
    return tx.flowRoom.create({
      data: { flowId, roomTypeId: dto.roomTypeId, defaultOrder: dto.defaultOrder },
      include: { roomType: true },
    });
  }

  deleteFlowRoom(flowId: number, roomTypeId: number, tx: DbClient = this.prisma) {
    return tx.flowRoom.delete({
      where: { flowId_roomTypeId: { flowId, roomTypeId } },
    });
  }

  deleteFlowRoomDependencies(flowId: number, roomTypeId?: number, tx: DbClient = this.prisma) {
    return tx.flowRoomDependency.deleteMany({
      where: roomTypeId === undefined
        ? { flowId }
        : {
            flowId,
            OR: [{ roomTypeId }, { requiredRoomTypeId: roomTypeId }],
          },
    });
  }

  findDependency(flowId: number, roomTypeId: number, requiredRoomTypeId: number, tx: DbClient = this.prisma) {
    return tx.flowRoomDependency.findUnique({
      where: {
        flowId_roomTypeId_requiredRoomTypeId: {
          flowId,
          roomTypeId,
          requiredRoomTypeId,
        },
      },
    });
  }

  createDependency(flowId: number, dto: FlowRoomDependencyItemDto, tx: DbClient = this.prisma) {
    return tx.flowRoomDependency.create({
      data: {
        flowId,
        roomTypeId: dto.roomTypeId,
        requiredRoomTypeId: dto.requiredRoomTypeId,
      },
      include: {
        roomType: { select: { id: true, name: true } },
        requiredRoomType: { select: { id: true, name: true } },
      },
    });
  }

  deleteDependency(flowId: number, dto: FlowRoomDependencyItemDto, tx: DbClient = this.prisma) {
    return tx.flowRoomDependency.delete({
      where: {
        flowId_roomTypeId_requiredRoomTypeId: {
          flowId,
          roomTypeId: dto.roomTypeId,
          requiredRoomTypeId: dto.requiredRoomTypeId,
        },
      },
    });
  }

  transaction<T>(callback: (tx: Prisma.TransactionClient) => Promise<T>) {
    return this.prisma.$transaction(callback);
  }
}