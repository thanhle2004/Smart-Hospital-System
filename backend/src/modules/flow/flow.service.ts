import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateFlowDto, FlowRoomDependencyItemDto, FlowRoomItemDto } from './dto/create-flow.dto';
import { UpdateFlowDto } from './dto/update-flow.dto';
import { UpsertFlowRoomsDto } from './dto/upsert-flow-rooms.dto';
import { FlowRepository } from './flow.repository';

@Injectable()
export class FlowService {
  constructor(private readonly repo: FlowRepository) {}

  // GET all flows (detailed)
  findAll() {
    return this.repo.findAll();
  }

  // GET all flows (name only, for dropdowns)
  findAllSimple() {
    return this.repo.findAllSimple();
  }

  // GET flow by ID (detailed)
  async findOne(id: number) {
    const flow = await this.repo.findOne(id);
    if (!flow) throw new NotFoundException(`Flow #${id} not found`);
    return flow;
  }

  // POST create new flow
  async create(dto: CreateFlowDto) {
    await this.assertRoomTypesExist(dto.rooms.map((r) => r.roomTypeId));
    this.assertUniqueOrders(dto.rooms);

    if (dto.dependencies?.length) {
      this.assertDependenciesValid(dto.rooms, dto.dependencies);
    }

    return this.repo.create(dto);
  }

  // PATCH update flow details (currently only name can be updated)
  async update(id: number, dto: UpdateFlowDto) {
    await this.findOne(id);
    return this.repo.update(id, dto);
  }

  //UPDATE flow rooms & dependencies in bulk
  async upsertRooms(id: number, dto: UpsertFlowRoomsDto) {
    await this.findOne(id);
    await this.assertRoomTypesExist(dto.rooms.map((r) => r.roomTypeId));
    this.assertUniqueOrders(dto.rooms);

    if (dto.dependencies?.length) {
      this.assertDependenciesValid(dto.rooms, dto.dependencies);
    }

    return this.repo.transaction(async (tx) => {
      // Remove existing rooms & dependencies before adding the new ones. This ensures that the update is atomic and consistent.
      await this.repo.deleteFlowRoomDependencies(id, undefined, tx);
      await tx.flowRoom.deleteMany({ where: { flowId: id } });

      await tx.flowRoom.createMany({
        data: dto.rooms.map((r) => ({
          flowId: id,
          roomTypeId: r.roomTypeId,
          defaultOrder: r.defaultOrder,
        })),
      });

      if (dto.dependencies?.length) {
        await tx.flowRoomDependency.createMany({
          data: dto.dependencies.map((d) => ({
            flowId: id,
            roomTypeId: d.roomTypeId,
            requiredRoomTypeId: d.requiredRoomTypeId,
          })),
        });
      }

      return this.repo.findOne(id, tx);
    });
  }

  // Remove a flow, but first check if there are any active visits using this flow. If there are, prevent deletion to avoid orphaned visits.
  async remove(id: number) {
    await this.findOne(id);

    const activeVisits = await this.repo.countActiveVisits(id);
    if (activeVisits > 0) {
      throw new ConflictException(
        `Cannot delete: Flow #${id} has ${activeVisits} active visit(s)`,
      );
    }

    return this.repo.delete(id);
  }

  // Add a single room to the flow.
  async addRoom(flowId: number, dto: FlowRoomItemDto) {
    const flow = await this.findOne(flowId);

    const roomType = await this.repo.findRoomType(dto.roomTypeId);
    if (!roomType) {
      throw new NotFoundException(`RoomType #${dto.roomTypeId} not found`);
    }

    if (flow.flowRooms.some((fr) => fr.roomTypeId === dto.roomTypeId)) {
      throw new ConflictException(
        `RoomType #${dto.roomTypeId} is already in Flow #${flowId}`,
      );
    }

    if (flow.flowRooms.some((fr) => fr.defaultOrder === dto.defaultOrder)) {
      throw new ConflictException(
        `defaultOrder ${dto.defaultOrder} is already taken in Flow #${flowId}`,
      );
    }

    return this.repo.createFlowRoom(flowId, dto);
  }

  // Remove a single room from the flow. Also removes any dependencies related to that room to maintain data integrity.
  async removeRoom(flowId: number, roomTypeId: number) {
    await this.findOne(flowId);

    await this.repo.deleteFlowRoomDependencies(flowId, roomTypeId);

    return this.repo.deleteFlowRoom(flowId, roomTypeId);
  }

  // Add a dependency between rooms in the flow. Validates that the dependency is logical (e.g., a room cannot depend on itself, and both rooms must be part of the flow).
  async addDependency(flowId: number, dto: FlowRoomDependencyItemDto) {
    const flow = await this.findOne(flowId);

    this.assertDependenciesValid(
      flow.flowRooms.map((fr) => ({
        roomTypeId: fr.roomTypeId,
        defaultOrder: fr.defaultOrder,
      })),
      [dto],
    );

    const exists = await this.repo.findDependency(flowId, dto.roomTypeId, dto.requiredRoomTypeId);
    if (exists) throw new ConflictException('This dependency already exists');

    return this.repo.createDependency(flowId, dto);
  }

  // Remove a dependency between rooms in the flow.
  async removeDependency(flowId: number, dto: FlowRoomDependencyItemDto) {
    await this.findOne(flowId);

    return this.repo.deleteDependency(flowId, dto);
  }

  // Helper method to check if all provided roomTypeIds exist in the database. This is used to validate incoming data before performing operations.
  private async assertRoomTypesExist(roomTypeIds: number[]) {
    const unique = [...new Set(roomTypeIds)];
    const found = await this.repo.findRoomTypes(unique);
    const missing = unique.filter((id) => !found.some((f) => f.id === id));
    if (missing.length) {
      throw new NotFoundException(`RoomType(s) not found: [${missing.join(', ')}]`);
    }
  }

  // Helper method to ensure that the defaultOrder values for rooms in a flow are unique. This prevents logical conflicts in the flow sequence.
  private assertUniqueOrders(rooms: FlowRoomItemDto[]) {
    const orders = rooms.map((r) => r.defaultOrder);
    if (new Set(orders).size !== orders.length) {
      throw new BadRequestException(
        'defaultOrder values must be unique within a flow',
      );
    }
  }

  // Helper method to validate that room dependencies are logical and consistent with the rooms defined in the flow. It checks for self-dependencies, ensures that all referenced room types exist in the flow, and that there are no circular dependencies.
  private assertDependenciesValid(
    rooms: FlowRoomItemDto[],
    dependencies: FlowRoomDependencyItemDto[],
  ) {
    const roomTypeIds = rooms.map((r) => r.roomTypeId);

    for (const dep of dependencies) {
      if (dep.roomTypeId === dep.requiredRoomTypeId) {
        throw new BadRequestException(
          `RoomType #${dep.roomTypeId} cannot depend on itself`,
        );
      }
      if (!roomTypeIds.includes(dep.roomTypeId)) {
        throw new BadRequestException(
          `RoomType #${dep.roomTypeId} is not in this flow`,
        );
      }
      if (!roomTypeIds.includes(dep.requiredRoomTypeId)) {
        throw new BadRequestException(
          `RoomType #${dep.requiredRoomTypeId} is not in this flow`,
        );
      }
    }
  }
}