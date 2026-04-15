import {
  Injectable,
  NotFoundException,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PriorityService } from '../priority/priority.service';
import { VisitFlowService } from '../visit-flow/visit-flow.service';
import { RoomService } from '../room/room.service';
import { createHmac, timingSafeEqual } from 'crypto';
import { VisitRepository } from './visit.repository';

@Injectable()
export class VisitService {
  constructor(
    private readonly repo: VisitRepository,
    private priorityService: PriorityService,
    private visitFlowService: VisitFlowService,
    private roomService: RoomService,
  ) {}

  private getVisitAccessSecret() {
    return process.env.VISIT_ACCESS_SECRET || process.env.JWT_ACCESS_SECRET || 'dev-visit-access-secret';
  }

  private buildVisitAccessToken(visitId: string, patientId: string) {
    const payload = `${visitId}.${patientId}`;
    const signature = createHmac('sha256', this.getVisitAccessSecret())
      .update(payload)
      .digest('hex');
    return `${payload}.${signature}`;
  }

  private verifyVisitAccessToken(visitId: string, patientId: string, token: string) {
    const expected = this.buildVisitAccessToken(visitId, patientId);
    const expectedBuf = Buffer.from(expected);
    const providedBuf = Buffer.from(token);
    if (expectedBuf.length !== providedBuf.length) return false;
    return timingSafeEqual(expectedBuf, providedBuf);
  }

  async checkIn(data: {
    patientId: string;
    flowId: number;
    age?: number;
    patientTypeId?: number;
    isEmergency?: boolean;
  }) {
    
    const activeVisit = await this.repo.findActiveVisitByPatient(data.patientId);

    if (activeVisit) {
      throw new ConflictException(
        'You already have an active visit. Please complete or cancel it before starting a new one.',
      );
    }

    const result = await this.repo.transaction(async (tx) => {
      const visit = await this.repo.createVisit({
        patientId: data.patientId,
        flowId: data.flowId,
        status: 'WAITING',
      }, tx);

      await this.visitFlowService.copyFromTemplate(visit.id, data.flowId, tx);

      const rule = await this.priorityService.applyPriority(
        {
          age: data.age,
          patientTypeId: data.patientTypeId,
          isEmergency: data.isEmergency,
        },
        tx,
      );

      if (rule) {
        await this.repo.updateVisit(visit.id, { appliedPriorityRuleId: rule.id }, tx);
      }

      await this.addToCentralQueue(visit.id, rule?.priorityValue ?? 0, tx);

      const firstRoomId = await this.selectNextRoom(visit.id, tx);
      if (firstRoomId) {
        await this.createAndQueueVisitRoom(visit.id, firstRoomId, tx);
      }

      await this.monitorHrrn(tx);
      return visit;
    });

    return this.serializeBigInt({
      ...result,
      visitAccessToken: this.buildVisitAccessToken(result.id, result.patientId),
    });
  }

  // CALL PATIENT 
  async callPatient(visitRoomId: number) {
    const visitRoom = await this.repo.findVisitRoomById(visitRoomId);

    if (!visitRoom) throw new NotFoundException('VisitRoom not found');
    if (visitRoom.status !== 'WAITING') {
      throw new ConflictException('Only WAITING patients can be called');
    }

    const updated = await this.repo.updateVisitRoom(visitRoomId, {
      status: 'IN_PROGRESS',
      startTime: new Date(),
    });
 
    if (updated.roomId) {
      await this.roomService.emitQueueEvent(updated.roomId);
    }
 
    return updated;
  }

  // SKIP PATIENT
async skipPatient(visitRoomId: number) {
  const visitRoom = await this.repo.findVisitRoomById(visitRoomId);

  if (!visitRoom) throw new NotFoundException('VisitRoom not found');

  const updated = await this.repo.transaction(async (tx) => {
    const result = await this.repo.updateVisitRoom(visitRoomId, { status: 'SKIPPED', endTime: new Date() }, tx);

    const nextRoomId = await this.selectNextRoom(visitRoom.visitId, tx);
    if (nextRoomId) {
      await this.createAndQueueVisitRoom(visitRoom.visitId, nextRoomId, tx);
      await this.resetSkippedSteps(visitRoom.visitId, tx);
    } else {
      await this.repo.updateVisitStatus(visitRoom.visitId, 'COMPLETED', tx);
    }

    return result;
  });

  // Emit now works correctly
  if (visitRoom.roomId) {
    await this.roomService.emitQueueEvent(visitRoom.roomId);
  }

  return updated;
}

  // COMPLETE VISIT ROOM
async completeVisitRoom(visitRoomId: number) {
  const result = await this.repo.transaction(async (tx) => {
    const visitRoom = await this.repo.findVisitRoomById(visitRoomId, tx);

    if (!visitRoom) throw new NotFoundException('VisitRoom not found');

    await this.repo.updateVisitRoom(visitRoomId, { status: 'COMPLETED', endTime: new Date() }, tx);

    const nextRoomId = await this.selectNextRoom(visitRoom.visitId, tx);

    if (!nextRoomId) {
      await this.repo.updateVisitStatus(visitRoom.visitId, 'COMPLETED', tx);
      return { flowCompleted: true, roomId: visitRoom.roomId };
    }

    const nextVisitRoom = await this.createAndQueueVisitRoom(
      visitRoom.visitId,
      nextRoomId,
      tx,
    );

    await this.resetSkippedSteps(visitRoom.visitId, tx);

    await this.monitorHrrn(tx);

    return { flowCompleted: false, nextVisitRoom, roomId: visitRoom.roomId };
  });

  // Emit now works correctly
  if (result.roomId) {
    await this.roomService.emitQueueEvent(result.roomId);
  }

  return result;
}

  // HELPER METHODS
  private async addToCentralQueue(visitId: string, priority: number, tx: any) {
    return this.repo.createCentralQueue(visitId, priority, tx);
  }

  async getCentralQueue() {
    const queue = await this.repo.findCentralQueue();

    return this.serializeBigInt(
      queue
        .map((item) => ({
          ...item,
          effectivePriority: item.manualPriority ?? item.calculatedPriority ?? 0,
        }))
        .sort((a, b) => {
          const priorityDiff = b.effectivePriority - a.effectivePriority;
          if (priorityDiff !== 0) return priorityDiff;

          const queueTimeDiff = new Date(a.queueTime).getTime() - new Date(b.queueTime).getTime();
          if (queueTimeDiff !== 0) return queueTimeDiff;

          return String(a.visitId).localeCompare(String(b.visitId));
        }),
    );
  }

  private async createAndQueueVisitRoom(visitId: string, roomId: number, tx: any) {
    const room = await this.repo.findRoomById(roomId, tx);
    if (!room) throw new NotFoundException('Room not found');
    if (!room.roomTypeId) throw new ConflictException('Room must have a type');

    const visitRoom = await this.repo.createVisitRoom({
      visitId,
      roomId,
      roomTypeId: room.roomTypeId,
      status: 'WAITING',
    }, tx);

    await this.repo.createRoomQueue(visitRoom.id, tx);

    return visitRoom;
  }

  private async selectNextRoom(visitId: string, tx: Prisma.TransactionClient): Promise<number | null> {
    await this.repo.lockRooms(tx); 

    const visit = await this.repo.findVisitById(visitId, tx);

    if (!visit) throw new NotFoundException('Visit not found');

    const completedRTIds = visit.visitRooms
      .filter(vr => vr.status === 'COMPLETED')
      .map(vr => vr.roomTypeId);

    const steps = await this.repo.findVisitFlowSteps(visitId, tx);

    // Keep unfinished, non-skipped steps that satisfy dependencies
    const dependencies = await this.repo.findVisitFlowDependencies(tx);

    const eligibleSteps = steps.filter(step => {
      if (step.isSkipped) return false; // Skip steps already marked as skipped
      if (completedRTIds.includes(step.roomTypeId)) return false;

      const required = dependencies
        .filter(d => d.visitFlowId === step.id)
        .map(d => d.requiredVisitFlowId);

      return required.every(reqId =>
        visit.visitRooms.some(vr => 
          vr.roomTypeId === steps.find(s => s.id === reqId)?.roomTypeId && 
          vr.status === 'COMPLETED'
        )
      );
    });

    if (eligibleSteps.length === 0) return null;

    const candidateRooms = await this.repo.findCandidateRooms(eligibleSteps.map(s => s.roomTypeId), tx);

    if (candidateRooms.length === 0) return null;

    const roomsWithDoctors = candidateRooms.filter((room) => room.capacity > 0);
    const allRoomsNoDoctors = roomsWithDoctors.length === 0;
    const preferredRooms = allRoomsNoDoctors ? candidateRooms : roomsWithDoctors;

    let bestRoomId: number | null = null;
    let minWaiting = Infinity;

    for (const room of preferredRooms) {
      const qCount = await this.repo.countRoomQueue(room.id, tx);

      // Prefer rooms with doctors; if none have doctors yet, use temporary capacity = 1.
      const effectiveCapacity = allRoomsNoDoctors ? 1 : room.capacity;
      const waiting = Math.floor(qCount / effectiveCapacity) * room.avgProcessTime;
      if (waiting < minWaiting) {
        minWaiting = waiting;
        bestRoomId = room.id;
      }
    }

    return bestRoomId;
  }

  async getVisitDetail(visitId: string, accessToken: string) {
    const visit = await this.repo.findVisitDetail(visitId);
    if (!visit) throw new NotFoundException('Visit not found');

    if (!accessToken || !this.verifyVisitAccessToken(visit.id, visit.patientId, accessToken)) {
      throw new UnauthorizedException('Invalid visit access token');
    }

    return this.serializeBigInt(visit);
  }

  async getVisitsByPatient(patientId: string) {
    const visits = await this.repo.findVisitsByPatient(patientId);
    return visits.map((v) =>
      this.serializeBigInt({
        ...v,
        visitAccessToken: this.buildVisitAccessToken(v.id, v.patientId),
      }),
    );
  }

  private async monitorHrrn(tx: any) {
    return;
  }

  private serializeBigInt(data: any) {
    return JSON.parse(
      JSON.stringify(data, (_, value) =>
        typeof value === 'bigint' ? value.toString() : value,
      ),
    );
  }

  private async syncVisitStatus(visitId: string) {
    const allVisitRooms = await this.repo.findVisitRoomStatuses(visitId);
 
    const allDone = allVisitRooms.every(
      (vr) => vr.status === 'COMPLETED' || vr.status === 'SKIPPED',
    );
 
    if (allDone) {
      await this.repo.updateVisitStatus(visitId, 'COMPLETED');
    }
  }

  private async resetSkippedSteps(visitId: string, tx: Prisma.TransactionClient) {
    await this.repo.resetSkippedSteps(visitId, tx);
  }
}