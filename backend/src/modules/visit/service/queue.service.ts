import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';

@Injectable()
export class QueueService {
  constructor(private prisma: PrismaService) {}

  async addToCentralQueue(visitId: number, priority: number) {
    const last = await this.prisma.centralQueue.findFirst({
      orderBy: { globalSequence: 'desc' },
    });

    return this.prisma.centralQueue.create({
      data: {
        visitId,
        calculatedPriority: priority,
        globalSequence: last ? Number(last.globalSequence) + 1 : 1,
      },
    });
  }

  async addToRoomQueue(visitRoomId: number) {
    return this.prisma.roomQueue.create({
      data: {
        visitRoomId,
      },
    });
  }
}