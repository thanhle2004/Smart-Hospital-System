import { Injectable } from '@nestjs/common';
import { Prisma, VisitFlow, VisitRoomStatusEnum } from '@prisma/client';
import { PrismaService } from '../../shared/prisma/prisma.service';
import { CreateVisitFlowDto } from './dto/create-visit-flow.dto';
import { UpdateVisitFlowDto } from './dto/update-visit-flow.dto';

type DbClient = PrismaService | Prisma.TransactionClient;

@Injectable()
export class VisitFlowRepository {
  constructor(private readonly prisma: PrismaService) {}

  findLockedVisitRoom(visitId: string, roomTypeId: number, tx: DbClient = this.prisma) {
    return tx.visitRoom.findFirst({
      where: {
        visitId,
        roomTypeId,
        status: {
          in: [VisitRoomStatusEnum.IN_PROGRESS, VisitRoomStatusEnum.COMPLETED],
        },
      },
    });
  }

  findFlowRooms(flowId: number, tx: DbClient = this.prisma) {
    return tx.flowRoom.findMany({
      where: { flowId },
      orderBy: { defaultOrder: 'asc' },
    });
  }

  findVisitFlowByVisitRoom(visitId: string, roomTypeId: number, tx: DbClient = this.prisma) {
    return tx.visitFlow.findUnique({
      where: { visitId_roomTypeId: { visitId, roomTypeId } },
    });
  }

  createVisitFlow(visitId: string, roomTypeId: number, orderIndex: number, isAddedManually = false, tx: DbClient = this.prisma) {
    return tx.visitFlow.create({
      data: { visitId, roomTypeId, orderIndex, isAddedManually },
    });
  }

  findFlowDependencies(flowId: number, tx: DbClient = this.prisma) {
    return tx.flowRoomDependency.findMany({ where: { flowId } });
  }

  findVisitFlowDependenciesByStep(visitFlowId: number, tx: DbClient = this.prisma) {
    return tx.visitFlowDependency.findMany({
      where: { visitFlowId },
      select: { requiredVisitFlowId: true },
    });
  }

  findVisitFlowsByVisit(visitId: string, tx: DbClient = this.prisma) {
    return tx.visitFlow.findMany({
      where: { visitId },
      include: {
        roomType: true,
        dependencies: true,
        requiredBy: true,
      },
      orderBy: { orderIndex: 'asc' },
    });
  }

  findVisitFlowsDetailedByVisit(visitId: string, tx: DbClient = this.prisma) {
    return tx.visitFlow.findMany({
      where: { visitId },
      include: {
        roomType: true,
        dependencies: {
          include: {
            requiredVisitFlow: {
              include: { roomType: true },
            },
          },
        },
        requiredBy: true,
      },
      orderBy: { orderIndex: 'asc' },
    });
  }

  findVisitRoomsByVisit(visitId: string, tx: DbClient = this.prisma) {
    return tx.visitRoom.findMany({
      where: { visitId },
      select: {
        roomTypeId: true,
        status: true,
      },
    });
  }

  findVisitRoomById(id: number, tx: DbClient = this.prisma) {
    return tx.visitRoom.findUnique({ where: { id } });
  }

  findVisitById(visitId: string, tx: DbClient = this.prisma) {
    return tx.visit.findUnique({
      where: { id: visitId },
      include: { visitRooms: true },
    });
  }

  findVisitFlowById(id: number, tx: DbClient = this.prisma) {
    return tx.visitFlow.findUnique({ where: { id } });
  }

  findLastVisitFlowByVisit(visitId: string, tx: DbClient = this.prisma) {
    return tx.visitFlow.findFirst({
      where: { visitId },
      orderBy: { orderIndex: 'desc' },
    });
  }

  createVisitFlowStep(dto: CreateVisitFlowDto, tx: DbClient = this.prisma) {
    return tx.visitFlow.create({
      data: {
        visitId: dto.visitId,
        roomTypeId: dto.roomTypeId,
        orderIndex: dto.orderIndex ?? 999,
        isAddedManually: true,
      },
    });
  }

  createDependencies(visitFlowId: number, requiredVisitFlowIds: number[], tx: DbClient = this.prisma) {
    return tx.visitFlowDependency.createMany({
      data: requiredVisitFlowIds.map((requiredVisitFlowId) => ({
        visitFlowId,
        requiredVisitFlowId,
      })),
      skipDuplicates: true,
    });
  }

  findVisitFlowWithRelations(id: number, tx: DbClient = this.prisma) {
    return tx.visitFlow.findUnique({
      where: { id },
      include: {
        roomType: true,
        dependencies: true,
        requiredBy: true,
      },
    });
  }

  updateVisitFlow(id: number, dto: UpdateVisitFlowDto, tx: DbClient = this.prisma) {
    return tx.visitFlow.update({ where: { id }, data: dto });
  }

  updateVisitFlowsByIds(ids: number[], tx: DbClient = this.prisma) {
    return tx.visitFlow.updateMany({
      where: { id: { in: ids } },
      data: { isSkipped: true },
    });
  }

  resetSkippedSteps(visitId: string, tx: DbClient = this.prisma) {
    return tx.visitFlow.updateMany({
      where: { visitId, isSkipped: true },
      data: { isSkipped: false },
    });
  }

  deleteVisitFlowDependenciesByVisitFlow(id: number, tx: DbClient = this.prisma) {
    return tx.visitFlowDependency.deleteMany({
      where: { OR: [{ visitFlowId: id }, { requiredVisitFlowId: id }] },
    });
  }

  deleteVisitFlow(id: number, tx: DbClient = this.prisma) {
    return tx.visitFlow.delete({ where: { id } });
  }

  transaction<T>(callback: (tx: Prisma.TransactionClient) => Promise<T>) {
    return this.prisma.$transaction(callback);
  }
}