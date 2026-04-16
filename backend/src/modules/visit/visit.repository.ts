import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../shared/prisma/prisma.service';

type DbClient = PrismaService | Prisma.TransactionClient;

@Injectable()
export class VisitRepository {
  constructor(private readonly prisma: PrismaService) {}

  findActiveVisitByPatient(patientId: string, tx: DbClient = this.prisma) {
    return tx.visit.findFirst({
      where: {
        patientId,
        status: {
          in: ['WAITING', 'IN_PROGRESS'],
        },
      },
    });
  }

  createVisit(data: { patientId: string; flowId: number; status: 'WAITING' }, tx: DbClient = this.prisma) {
    return tx.visit.create({ data });
  }

  updateVisit(id: string, data: Record<string, unknown>, tx: DbClient = this.prisma) {
    return tx.visit.update({ where: { id }, data });
  }

  findVisitRoomById(id: number, tx: DbClient = this.prisma) {
    return tx.visitRoom.findUnique({ where: { id } });
  }

  updateVisitRoom(id: number, data: Record<string, unknown>, tx: DbClient = this.prisma) {
    return tx.visitRoom.update({ where: { id }, data });
  }

  findVisitRoomByVisitAndRoomType(visitId: string, roomTypeId: number, tx: DbClient = this.prisma) {
    return tx.visitRoom.findFirst({
      where: { visitId, roomTypeId },
      orderBy: { createdAt: 'asc' },
    });
  }

  findLastVisitFlow(visitId: string, tx: DbClient = this.prisma) {
    return tx.visitFlow.findFirst({
      where: { visitId },
      orderBy: { orderIndex: 'desc' },
    });
  }

  createCentralQueue(visitId: string, calculatedPriority: number, tx: DbClient = this.prisma) {
    return tx.centralQueue.create({
      data: { visitId, calculatedPriority },
    });
  }

  findCentralQueue(tx: DbClient = this.prisma) {
    return tx.centralQueue.findMany({
      include: {
        visit: {
          include: {
            patient: { include: { patientType: true } },
            flow: true,
            appliedPriorityRule: true,
          },
        },
      },
    });
  }

  createVisitRoom(data: { visitId: string; roomId: number; roomTypeId: number; status: 'WAITING' }, tx: DbClient = this.prisma) {
    return tx.visitRoom.create({ data });
  }

  createRoomQueue(visitRoomId: number, tx: DbClient = this.prisma) {
    return tx.roomQueue.create({ data: { visitRoomId } });
  }

  findRoomById(id: number, tx: DbClient = this.prisma) {
    return tx.room.findUnique({ where: { id } });
  }

  countInProgressByRoom(roomId: number, tx: DbClient = this.prisma) {
    return tx.visitRoom.count({
      where: { roomId, status: 'IN_PROGRESS' },
    });
  }

  findVisitById(visitId: string, tx: DbClient = this.prisma) {
    return tx.visit.findUnique({
      where: { id: visitId },
      include: { visitRooms: true },
    });
  }

  findVisitFlowSteps(visitId: string, tx: DbClient = this.prisma) {
    return tx.visitFlow.findMany({
      where: { visitId },
      orderBy: { orderIndex: 'asc' },
    });
  }

  findVisitFlowDependencies(tx: DbClient = this.prisma) {
    return tx.visitFlowDependency.findMany();
  }

  findCandidateRooms(roomTypeIds: number[], tx: DbClient = this.prisma) {
    return tx.room.findMany({
      where: {
        roomTypeId: { in: roomTypeIds },
        isActive: true,
      },
    });
  }

  countRoomQueue(roomId: number, tx: DbClient = this.prisma) {
    return tx.roomQueue.count({
      where: { visitRoom: { roomId, status: 'WAITING' } },
    });
  }

  findVisitDetail(visitId: string, tx: DbClient = this.prisma) {
    return tx.visit.findUnique({
      where: { id: visitId },
      include: {
        patient: true,
        visitFlows: { include: { roomType: true }, orderBy: { orderIndex: 'asc' } },
        visitRooms: { include: { room: true } },
        centralQueue: true,
      },
    });
  }

  findVisitsByPatient(patientId: string, tx: DbClient = this.prisma) {
    return tx.visit.findMany({
      where: { patientId },
      include: {
        visitFlows: { include: { roomType: true } },
        visitRooms: { include: { room: true } },
      },
      orderBy: { id: 'desc' },
    });
  }

  findWaitingVisitRooms(visitId: string, tx: DbClient = this.prisma) {
    return tx.visitRoom.findMany({
      where: { visitId, status: 'WAITING' },
      include: { visit: true },
    });
  }

  findVisitRoomStatuses(visitId: string, tx: DbClient = this.prisma) {
    return tx.visitRoom.findMany({
      where: { visitId },
      select: { status: true },
    });
  }

  updateVisitFlows(visitId: string, tx: DbClient = this.prisma) {
    return tx.visitFlow.updateMany({
      where: { visitId, isSkipped: true },
      data: { isSkipped: false },
    });
  }

  resetSkippedSteps(visitId: string, tx: DbClient = this.prisma) {
    return tx.visitFlow.updateMany({
      where: { visitId, isSkipped: true },
      data: { isSkipped: false },
    });
  }

  updateVisitStatus(visitId: string, status: 'COMPLETED', tx: DbClient = this.prisma) {
    return tx.visit.update({ where: { id: visitId }, data: { status } });
  }

  lockRooms(tx: DbClient = this.prisma) {
    return tx.$executeRaw`SELECT id FROM Room FOR UPDATE`;
  }

  transaction<T>(callback: (tx: Prisma.TransactionClient) => Promise<T>) {
    return this.prisma.$transaction(callback);
  }
}