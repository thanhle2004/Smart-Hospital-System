// modules/room/room.service.ts
import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { RoomRepository } from './room.repository';
import { RoomGateway } from './room.gateway';
import { CreateRoomDto } from './dto/create-room.dto';
import { UpdateRoomDto } from './dto/update-room.dto';
import { Prisma } from '@prisma/client';

@Injectable()
export class RoomService {
  constructor(
    private readonly prisma: RoomRepository,
    private roomGateway: RoomGateway, // ← inject gateway
  ) {}

  // ─── Basic CRUD ───────────────────────────────────────────────────────────

  async findAll() {
    return this.prisma.room.findMany({
      include: {
        roomType: true,
        roomAssignments: {
          where: { isActive: true },
          include: {
            doctor: { select: { id: true, email: true, profile: true } },
          },
        },
      },
      orderBy: [{ roomTypeId: 'asc' }, { roomNumber: 'asc' }],
    });
  }

  async findOne(id: number) {
    const room = await this.prisma.room.findUnique({
      where: { id },
      include: {
        roomType: true,
        roomAssignments: {
          where: { isActive: true },
          include: {
            doctor: { select: { id: true, email: true, profile: true } },
          },
        },
      },
    });
    if (!room) throw new NotFoundException(`Room #${id} not found`);
    return room;
  }

  async create(dto: CreateRoomDto) {
    if (dto.roomTypeId != null) {
      await this.assertRoomTypeExists(dto.roomTypeId);
    }

    const { capacity: _capacity, roomTypeId, avgProcessTime, ...roomData } = dto;

    const data = {
      ...roomData,
      capacity: 0,
      roomTypeId: roomTypeId ?? null,
      avgProcessTime: roomTypeId == null ? 0 : avgProcessTime,
    } as Prisma.RoomUncheckedCreateInput;

    return this.prisma.room.create({
      data,
      include: { roomType: true },
    });
  }

  async update(id: number, dto: UpdateRoomDto) {
    await this.findOne(id);
    if (dto.roomTypeId != null) {
      await this.assertRoomTypeExists(dto.roomTypeId);
    }

    const { capacity: _capacity, roomTypeId, avgProcessTime, ...roomData } = dto;

    const hasRoomTypeId = Object.prototype.hasOwnProperty.call(dto, 'roomTypeId');

    const data = {
      ...roomData,
      ...(Object.prototype.hasOwnProperty.call(dto, 'avgProcessTime')
        ? { avgProcessTime }
        : {}),
      ...(hasRoomTypeId
        ? { roomTypeId: roomTypeId ?? null }
        : {}),
      ...(hasRoomTypeId && roomTypeId == null ? { avgProcessTime: 0 } : {}),
    } as Prisma.RoomUncheckedUpdateInput;

    return this.prisma.room.update({
      where: { id },
      data,
      include: { roomType: true },
    });
  }

  async remove(id: number) {
    await this.findOne(id);
    const activeVisitRooms = await this.prisma.visitRoom.count({
      where: { roomId: id, status: { in: ['WAITING', 'IN_PROGRESS'] } },
    });
    if (activeVisitRooms > 0) {
      throw new ConflictException('Cannot delete: Room has active visit sessions');
    }
    return this.prisma.room.delete({ where: { id } });
  }

  // ─── Check-in / Check-out ─────────────────────────────────────────────────

  async checkIn(roomId: number, doctorId: string) {
    await this.findOne(roomId);

    const activeAssignment = await this.prisma.roomDoctor.findFirst({
      where: { doctorId, isActive: true },
    });

    if (activeAssignment) {
      throw new ConflictException('Doctor is already checked-in at another room');
    }

    const assignment = await this.prisma.$transaction(async (tx) => {
      const created = await tx.roomDoctor.create({
        data: { roomId, doctorId, isActive: true, startTime: new Date() },
      });

      await this.syncRoomCapacity(roomId, tx);
      return created;
    });

    // Realtime emit: doctor list changed
    await this.emitDoctorsEvent(roomId);

    return assignment;
  }

  async checkOut(roomId: number, doctorId: string) {
    const assignment = await this.prisma.roomDoctor.findFirst({
      where: { roomId, doctorId, isActive: true },
    });

    if (!assignment) {
      throw new NotFoundException(
        'No active check-in found for this doctor in this room',
      );
    }

    const updated = await this.prisma.$transaction(async (tx) => {
      const updatedAssignment = await tx.roomDoctor.update({
        where: { id: assignment.id },
        data: { isActive: false, endTime: new Date() },
      });

      await this.syncRoomCapacity(roomId, tx);
      return updatedAssignment;
    });

    // Realtime emit: doctor list changed
    await this.emitDoctorsEvent(roomId);

    return updated;
  }

  // ─── Queue ────────────────────────────────────────────────────────────────

  async getCurrentAssignment(doctorId: string) {
    return this.prisma.roomDoctor.findFirst({
      where: { doctorId, isActive: true },
      include: {
        room: {
          include: {
            roomType: true,
          },
        },
      },
      orderBy: { startTime: 'desc' },
    });
  }

  async getActiveDoctors(roomId: number) {
    const assignments = await this.prisma.roomDoctor.findMany({
      where: { roomId, isActive: true },
      include: {
        doctor: {
          select: {
            id: true,
            email: true,
            profile: {
              select: {
                fullName: true,
                avatarUrl: true,
              },
            },
          },
        },
      },
      orderBy: { startTime: 'asc' },
    });
    return assignments;
  }

  async getQueue(roomId: number) {
    const [waiting, current] = await Promise.all([
      this.prisma.visitRoom.findMany({
        where: { roomId, status: 'WAITING' },
        include: {
          visit: {
            include: {
              patient: { include: { patientType: true } },
              flow: {
                select: {
                  id: true,
                  name: true,
                },
              },
            },
          },
        },
        orderBy: { createdAt: 'asc' }, // FCFS
      }),
      this.prisma.visitRoom.findFirst({
        where: { roomId, status: 'IN_PROGRESS' },
        include: {
          visit: {
            include: {
              patient: { include: { patientType: true } },
              flow: {
                select: {
                  id: true,
                  name: true,
                },
              },
            },
          },
        },
      }),
    ]);

    return { waiting, current };
  }

  // ─── Active rooms (for dashboard) ────────────────────────────────────────

  async getActiveRooms() {
    const rooms = await this.prisma.room.findMany({
      where: {
        roomAssignments: { some: { isActive: true } },
        isActive: true,
      },
      include: {
        roomType: true,
        roomAssignments: {
          where: { isActive: true },
          include: {
            doctor: { select: { id: true, email: true, profile: true } },
          },
        },
      },
    });

    return Promise.all(
      rooms.map(async (room) => {
        const [current, waitingCount] = await Promise.all([
          this.prisma.visitRoom.findFirst({
            where: { roomId: room.id, status: 'IN_PROGRESS' },
            include: {
              visit: {
                include: {
                  patient: { include: { patientType: true } },
                },
              },
            },
          }),
          this.prisma.visitRoom.count({
            where: { roomId: room.id, status: 'WAITING' },
          }),
        ]);

        return { room, currentPatient: current, waitingCount };
      }),
    );
  }

  // ─── Stats (for dashboard) ────────────────────────────────────────────────

  async getDoctorStats() {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const [totalToday, waiting, inProgress, completed] = await Promise.all([
      this.prisma.visit.count({ where: { checkInTime: { gte: today } } }),
      this.prisma.visit.count({
        where: { checkInTime: { gte: today }, status: 'WAITING' },
      }),
      this.prisma.visit.count({
        where: { checkInTime: { gte: today }, status: 'IN_PROGRESS' },
      }),
      this.prisma.visit.count({
        where: { checkInTime: { gte: today }, status: 'COMPLETED' },
      }),
    ]);

    return { totalToday, waiting, inProgress, completed };
  }

  async getAdminDashboard() {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const [
      users,
      rooms,
      roomTypes,
      flows,
      patientTypes,
      priorityRules,
      patients,
      totalVisitsToday,
      ongoingVisits,
      completedVisitsToday,
      roomSnapshots,
    ] = await Promise.all([
      this.prisma.user.count(),
      this.prisma.room.count({
        where: {
          roomTypeId: { not: null },
        },
      }),
      this.prisma.roomType.count(),
      this.prisma.flow.count(),
      this.prisma.patientType.count(),
      this.prisma.priorityRule.count(),
      this.prisma.patient.count(),
      this.prisma.visit.count({ where: { checkInTime: { gte: today } } }),
      this.prisma.visit.count({
        where: {
          status: { in: ['WAITING', 'IN_PROGRESS'] },
        },
      }),
      this.prisma.visit.count({
        where: {
          checkInTime: { gte: today },
          status: 'COMPLETED',
        },
      }),
      this.prisma.room.findMany({
        where: {
          roomTypeId: { not: null },
        },
        include: {
          roomType: true,
          roomAssignments: {
            where: { isActive: true },
          },
        },
        orderBy: [{ roomTypeId: 'asc' }, { roomNumber: 'asc' }],
      }),
    ]);

    const roomsWithMetrics = await Promise.all(
      roomSnapshots.map(async (room) => {
        const waitingPatients = await this.prisma.visitRoom.count({
          where: { roomId: room.id, status: 'WAITING' },
        });

        return {
          id: room.id,
          name: room.name,
          roomNumber: room.roomNumber,
          roomTypeName: room.roomType?.name ?? 'Unassigned',
          activeDoctors: room.roomAssignments.length,
          waitingPatients,
          capacity: room.capacity,
        };
      }),
    );

    return {
      stats: {
        users,
        rooms,
        roomTypes,
        flows,
        patientTypes,
        priorityRules,
        patients,
        totalVisitsToday,
        ongoingVisits,
        completedVisitsToday,
      },
      rooms: roomsWithMetrics,
    };
  }

  // ─── Dashboard ────────────────────────────────────────────────────────────

  async getDashboard() {
    const roomTypes = await this.prisma.roomType.findMany({
      include: {
        rooms: {
          where: { isActive: true },
          include: {
            visitRooms: {
              where: { status: { in: ['WAITING', 'IN_PROGRESS'] } },
            },
          },
        },
      },
    });

    const result: any[] = [];

    for (const type of roomTypes) {
      const roomsData: any[] = [];

      for (const room of type.rooms) {
        const queueLength = room.visitRooms.length;
        const estimatedWaitingTime = await this.getEstimatedWaitingTime(room.id);

        roomsData.push({
          id: room.id,
          name: room.name,
          roomNumber: room.roomNumber,
          capacity: room.capacity,
          avgProcessTime: room.avgProcessTime,
          queueLength,
          estimatedWaitingTime,
        });
      }

      result.push({ id: type.id, name: type.name, rooms: roomsData });
    }

    return result;
  }

  async getEstimatedWaitingTime(roomId: number) {
    const room = await this.prisma.room.findUnique({
      where: { id: roomId },
      include: {
        visitRooms: {
          where: { status: { in: ['WAITING', 'IN_PROGRESS'] } },
        },
      },
    });

    if (!room) throw new NotFoundException('Room not found');

    const queueLength = room.visitRooms.length;
    if (queueLength === 0 || room.capacity <= 0) return 0;

    return Math.floor(queueLength / room.capacity) * room.avgProcessTime;
  }

  // ─── Internal: emit helpers ───────────────────────────────────────────────

  /**
    * Internal helper after check-in/out to emit doctors updates
   */
  async emitDoctorsEvent(roomId: number) {
    const room = await this.prisma.room.findUnique({
      where: { id: roomId },
      select: { capacity: true },
    });

    const doctors = await this.getActiveDoctors(roomId);

    this.roomGateway.emitDoctorsUpdated(roomId, {
      doctors,
      capacity: room?.capacity ?? 0,
    });
  }

  /**
    * Used by VisitService after call/complete/skip to emit queue updates
   */
  async emitQueueEvent(roomId: number) {
    const { waiting, current } = await this.getQueue(roomId);
    this.roomGateway.emitQueueUpdated(roomId, { waiting, current });
  }

  // ─── Private ──────────────────────────────────────────────────────────────

  private async assertRoomTypeExists(roomTypeId: number) {
    const rt = await this.prisma.roomType.findUnique({
      where: { id: roomTypeId },
    });
    if (!rt) throw new NotFoundException(`RoomType #${roomTypeId} not found`);
  }

  private async syncRoomCapacity(
    roomId: number,
    tx: RoomRepository | Prisma.TransactionClient = this.prisma,
  ) {
    const activeDoctors = await tx.roomDoctor.count({
      where: { roomId, isActive: true },
    });

    await tx.room.update({
      where: { id: roomId },
      data: { capacity: activeDoctors },
    });
  }
}