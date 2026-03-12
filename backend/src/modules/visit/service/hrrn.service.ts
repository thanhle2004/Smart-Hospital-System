import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';

@Injectable()
export class HrrnService {
  constructor(private prisma: PrismaService) {}

  async monitor() {
    const rooms = await this.prisma.room.findMany({
      include: {
        visitRooms: {
          where: { status: 'WAITING' },
        },
      },
    });

    const now = Date.now();

    const alerts: any[] = [];

    for (const room of rooms) {
      if (room.visitRooms.length === 0) continue;

      const waitingTimes = room.visitRooms.map(vr =>
        (now - new Date(vr.createdAt).getTime()) / 60000,
      );

      const avgWaitingTime =
        waitingTimes.reduce((a, b) => a + b, 0) /
        waitingTimes.length;

      const serviceTime = room.avgProcessTime || 1;

      const ratio = (avgWaitingTime + serviceTime) / serviceTime;

      if (ratio > 3) {
        const alert = {
          roomId: room.id,
          roomName: room.name,
          waitingPatients: room.visitRooms.length,
          avgWaitingTime: Number(avgWaitingTime.toFixed(2)),
          hrrnRatio: Number(ratio.toFixed(2)),
        };

        alerts.push(alert);

        console.log(
          `⚠️ HRRN ALERT - Room ${room.name}
Patients waiting: ${alert.waitingPatients}
Avg waiting: ${alert.avgWaitingTime} min
HRRN ratio: ${alert.hrrnRatio}`,
        );
      }
    }

    return alerts;
  }
}