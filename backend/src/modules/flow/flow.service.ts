import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class FlowService {
  constructor(private prisma: PrismaService) {}

  async createFlow(name: string) {
    return this.prisma.flow.create({
      data: { name },
    });
  }

  async findSimpleFlows() {
    return this.prisma.flow.findMany({
      select: {
        id: true,
        name: true,
      },
      orderBy: {
        name: 'asc',
      },
    });
  }

  async findAllFlows() {
    return this.prisma.flow.findMany({
      include: {
        flowRooms: {
          include: {
            roomType: true,
          },
          orderBy: {
            defaultOrder: 'asc',
          },
        },
        dependencies: {
          include: {
            roomType: true,
            requiredRoomType: true,
          },
        },
      },
    });
  }

  async findOneFlow(id: number) {
    const flow = await this.prisma.flow.findUnique({
      where: { id },
      include: {
        flowRooms: {
          include: {
            roomType: true,
          },
          orderBy: {
            defaultOrder: 'asc',
          },
        },
        dependencies: {
          include: {
            roomType: true,
            requiredRoomType: true,
          },
        },
      },
    });

    if (!flow) {
      throw new NotFoundException('Flow not found');
    }

    return flow;
  }

  async deleteFlow(id: number) {
    return this.prisma.flow.delete({
      where: { id },
    });
  }

  //////////////////////////////////////////////////
  // FLOW ROOM TYPE
  //////////////////////////////////////////////////

  async addRoomTypeToFlow(
    flowId: number,
    roomTypeId: number,
    defaultOrder: number,
  ) {
    return this.prisma.flowRoom.create({
      data: {
        flowId,
        roomTypeId,
        defaultOrder,
      },
    });
  }

  async removeRoomTypeFromFlow(flowId: number, roomTypeId: number) {
    return this.prisma.flowRoom.delete({
      where: {
        flowId_roomTypeId: {
          flowId,
          roomTypeId,
        },
      },
    });
  }

  //////////////////////////////////////////////////
  // ROOM TYPE DEPENDENCY
  //////////////////////////////////////////////////

  async addDependency(
    flowId: number,
    roomTypeId: number,
    requiredRoomTypeId: number,
  ) {
    return this.prisma.flowRoomDependency.create({
      data: {
        flowId,
        roomTypeId,
        requiredRoomTypeId,
      },
    });
  }

  async removeDependency(
    flowId: number,
    roomTypeId: number,
    requiredRoomTypeId: number,
  ) {
    return this.prisma.flowRoomDependency.delete({
      where: {
        flowId_roomTypeId_requiredRoomTypeId: {
          flowId,
          roomTypeId,
          requiredRoomTypeId,
        },
      },
    });
  }
}