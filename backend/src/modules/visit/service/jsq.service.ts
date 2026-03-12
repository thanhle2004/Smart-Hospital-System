import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import { Room } from '@prisma/client';

@Injectable()
export class JsqService {
  constructor(private prisma: PrismaService) {}

  async selectNextRoom(visitId: number) {
    const visit = await this.prisma.visit.findUnique({
      where: { id: visitId },
    });

    if (!visit) throw new Error('Visit not found');

    //////////////////////////////////////////////////
    // 1️⃣ room types trong flow
    //////////////////////////////////////////////////

    const flowRooms = await this.prisma.flowRoom.findMany({
      where: { flowId: visit.flowId },
      include: {
        roomType: {
          include: {
            rooms: true,
          },
        },
      },
      orderBy: { defaultOrder: 'asc' },
    });



    //////////////////////////////////////////////////
    // 2️⃣ room types đã đi
    //////////////////////////////////////////////////

    const visited = await this.prisma.visitRoom.findMany({
      where: { visitId },
      include: { room: true },
    });

    const visitedRoomTypeIds = visited.map(
      (v) => v.room.roomTypeId,
    );

    //////////////////////////////////////////////////
    // 3️⃣ room types còn lại
    //////////////////////////////////////////////////

    const remainingRoomTypes = flowRooms.filter(
      (fr) => !visitedRoomTypeIds.includes(fr.roomTypeId),
    );

    if (remainingRoomTypes.length === 0) return null;

    //////////////////////////////////////////////////
    // 4️⃣ dependency check
    //////////////////////////////////////////////////

    const dependencies =
      await this.prisma.flowRoomDependency.findMany({
        where: { flowId: visit.flowId },
      });

    const eligibleRoomTypes = remainingRoomTypes.filter(
      (fr) => {
        const required = dependencies
          .filter((d) => d.roomTypeId === fr.roomTypeId)
          .map((d) => d.requiredRoomTypeId);

        if (required.length === 0) return true;

        return required.every((req) =>
          visitedRoomTypeIds.includes(req),
        );
      },
    );

    if (eligibleRoomTypes.length === 0) return null;

    //////////////////////////////////////////////////
    // 5️⃣ tìm room tốt nhất
    //////////////////////////////////////////////////

    let bestRoom: Room | null = null;
    let minWaiting = Infinity;

    for (const fr of eligibleRoomTypes) {
      const rooms = fr.roomType.rooms;

      for (const room of rooms) {
        const queueLength =
          await this.prisma.visitRoom.count({
            where: {
              roomId: room.id,
              status: {
                in: ['WAITING', 'IN_PROGRESS'],
              },
            },
          });

        const estimatedWaitingTime =
        queueLength === 0
          ? 0
          : (Math.ceil(queueLength / room.capacity) - 1) * room.avgProcessTime;

        if (estimatedWaitingTime < minWaiting) {
          minWaiting = estimatedWaitingTime;
          bestRoom = room;
        }
      }
    }

    return bestRoom?.id ?? null;
  }
}