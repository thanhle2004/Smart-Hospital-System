import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../shared/prisma/prisma.service';

@Injectable()
export class RoomRepository {
  constructor(public readonly prisma: PrismaService) {}

  get room() {
    return this.prisma.room;
  }

  get visitRoom() {
    return this.prisma.visitRoom;
  }

  get roomDoctor() {
    return this.prisma.roomDoctor;
  }

  get visit() {
    return this.prisma.visit;
  }

  get roomType() {
    return this.prisma.roomType;
  }

  get user() {
    return this.prisma.user;
  }

  get flow() {
    return this.prisma.flow;
  }

  get patientType() {
    return this.prisma.patientType;
  }

  get priorityRule() {
    return this.prisma.priorityRule;
  }

  get patient() {
    return this.prisma.patient;
  }

  $transaction<T>(callback: (tx: Prisma.TransactionClient) => Promise<T>) {
    return this.prisma.$transaction(callback);
  }

  get $executeRaw() {
    return this.prisma.$executeRaw.bind(this.prisma);
  }
}