import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class RoomService {
  constructor(private prisma: PrismaService) {}

  //////////////////////////////////////////////////
  // CREATE ROOM
  //////////////////////////////////////////////////

  async create(data: {
    name: string;
    roomNumber: number;
    capacity?: number;
    roomTypeId: number;
  }) {
    const roomType = await this.prisma.roomType.findUnique({
      where: { id: data.roomTypeId },
    });

    if (!roomType) {
      throw new NotFoundException('RoomType not found');
    }

    return this.prisma.room.create({
      data: {
        name: data.name,
        roomNumber: data.roomNumber,
        roomTypeId: data.roomTypeId,
        capacity: data.capacity ?? roomType.defaultCapacity,
        avgProcessTime: roomType.avgProcessTime,
      },
      include: {
        roomType: true,
      },
    });
  }

  //////////////////////////////////////////////////
  // GET ROOMS
  //////////////////////////////////////////////////

  async findAll() {
    return this.prisma.room.findMany({
      include: {
        roomType: true,
        visitRooms: true,
      },
      orderBy: {
        roomNumber: 'asc',
      },
    });
  }

  async findOne(id: number) {
    const room = await this.prisma.room.findUnique({
      where: { id },
      include: {
        roomType: true,
        visitRooms: true,
      },
    });

    if (!room) {
      throw new NotFoundException('Room not found');
    }

    return room;
  }

  //////////////////////////////////////////////////
  // UPDATE ROOM
  //////////////////////////////////////////////////

  async update(
    id: number,
    data: Partial<{
      name: string;
      roomNumber: number;
      capacity: number;
      roomTypeId: number;
    }>,
  ) {
    return this.prisma.room.update({
      where: { id },
      data,
      include: {
        roomType: true,
      },
    });
  }

  //////////////////////////////////////////////////
  // DELETE ROOM
  //////////////////////////////////////////////////

  async remove(id: number) {
    return this.prisma.room.delete({
      where: { id },
    });
  }

  //////////////////////////////////////////////////
  // WAITING TIME
  //////////////////////////////////////////////////

  async getEstimatedWaitingTime(roomId: number) {
    const room = await this.prisma.room.findUnique({
      where: { id: roomId },
      include: {
        visitRooms: {
          where: {
            status: {
              in: ['WAITING', 'IN_PROGRESS'],
            },
          },
        },
      },
    });

    if (!room) throw new NotFoundException('Room not found');

    const queueLength = room.visitRooms.length;

    const estimatedWaitingTime =
        queueLength === 0
          ? 0
          : (Math.ceil(queueLength / room.capacity) - 1) * room.avgProcessTime;
    
    return estimatedWaitingTime;
  }

  //////////////////////////////////////////////////
  // DASHBOARD
  //////////////////////////////////////////////////

  async getDashboard() {
    const roomTypes = await this.prisma.roomType.findMany({
      include: {
        rooms: {
          include: {
            visitRooms: {
              where: {
                status: {
                  in: ['WAITING', 'IN_PROGRESS'],
                },
              },
            },
          },
        },
      },
    });

    return Promise.all(
      roomTypes.map(async (type) => ({
        id: type.id,
        name: type.name,

        rooms: await Promise.all(
          type.rooms.map(async (room) => {
            const queueLength = room.visitRooms.length;

            const estimatedWaitingTime =
              await this.getEstimatedWaitingTime(room.id);

            return {
              id: room.id,
              name: room.name,
              roomNumber: room.roomNumber,
              capacity: room.capacity,
              avgProcessTime: room.avgProcessTime,
              queueLength,
              estimatedWaitingTime,
            };
          }),
        ),
      })),
    );
  }
}