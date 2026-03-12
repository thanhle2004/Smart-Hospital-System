import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { PriorityService } from '../../priority/priority.service';
import { QueueService } from './queue.service';
import { JsqService } from './jsq.service';
import { HrrnService } from './hrrn.service';

@Injectable()
export class VisitService {
  constructor(
    private prisma: PrismaService,
    private priorityService: PriorityService,
    private queueService: QueueService,
    private jsqService: JsqService,
    private hrrnService: HrrnService,
  ) {}

  //////////////////////////////////////////////////
  // CHECK IN
  //////////////////////////////////////////////////

  async checkIn(data: {
    patientId: number;
    flowId: number;
    age?: number;
    patientTypeId?: number;
    isEmergency?: boolean;
  }) {
    const visit = await this.prisma.visit.create({
      data: {
        patientId: data.patientId,
        flowId: data.flowId,
        status: 'WAITING',
      },
    });

    //////////////////////////////////////////////////
    // priority
    //////////////////////////////////////////////////

    const rule = await this.priorityService.applyPriority({
      age: data.age,
      patientTypeId: data.patientTypeId,
      isEmergency: data.isEmergency,
    });

    if (rule) {
      await this.prisma.visit.update({
        where: { id: visit.id },
        data: {
          appliedPriorityRuleId: rule.id,
        },
      });
    }

    //////////////////////////////////////////////////
    // central queue
    //////////////////////////////////////////////////

    await this.queueService.addToCentralQueue(
      visit.id,
      rule?.priorityValue ?? 0,
    );

    //////////////////////////////////////////////////
    // JSQ scheduling
    //////////////////////////////////////////////////

    const roomId = await this.jsqService.selectNextRoom(
      visit.id,
    );

    if (roomId) {
      await this.createAndQueueVisitRoom(
        visit.id,
        roomId,
      );
    }

    //////////////////////////////////////////////////
    // HRRN monitor
    //////////////////////////////////////////////////

    await this.hrrnService.monitor();

    return visit;
  }

  //////////////////////////////////////////////////
  // COMPLETE ROOM
  //////////////////////////////////////////////////

  async completeVisitRoom(visitRoomId: number) {
    const visitRoom = await this.prisma.visitRoom.findUnique({
      where: { id: visitRoomId },
    });

    if (!visitRoom) {
      throw new Error('VisitRoom not found');
    }

    await this.prisma.visitRoom.update({
      where: { id: visitRoomId },
      data: {
        status: 'COMPLETED',
      },
    });

    //////////////////////////////////////////////////
    // next room
    //////////////////////////////////////////////////

    const nextRoomId =
      await this.jsqService.selectNextRoom(
        visitRoom.visitId,
      );

    if (!nextRoomId) {
      await this.prisma.visit.update({
        where: { id: visitRoom.visitId },
        data: {
          status: 'COMPLETED',
        },
      });

      return { flowCompleted: true };
    }

    const newVisitRoom =
      await this.createAndQueueVisitRoom(
        visitRoom.visitId,
        nextRoomId,
      );

    return {
      flowCompleted: false,
      nextVisitRoom: newVisitRoom,
    };
  }

  //////////////////////////////////////////////////
  // CREATE VISIT ROOM
  //////////////////////////////////////////////////

  private async createAndQueueVisitRoom(
    visitId: number,
    roomId: number,
  ) {
    const visitRoom = await this.prisma.visitRoom.create({
      data: {
        visitId,
        roomId,
        status: 'WAITING',
      },
    });

    await this.queueService.addToRoomQueue(
      visitRoom.id,
    );

    return visitRoom;
  }

  //////////////////////////////////////////////////
  // VISIT DETAIL
  //////////////////////////////////////////////////

  async getVisitDetail(visitId: number) {
    const visit = await this.prisma.visit.findUnique({
      where: { id: visitId },
      include: {
        flow: {
          include: {
            flowRooms: {
              include: {
                roomType: true,
              },
              orderBy: { defaultOrder: 'asc' },
            },
          },
        },
        visitRooms: {
          include: {
            room: true,
          },
        },
      },
    });

    if (!visit) {
      throw new Error('Visit not found');
    }

    return visit;
  }
}