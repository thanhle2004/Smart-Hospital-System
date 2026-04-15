import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { CreateRoomTypeDto } from './dto/create-room-type.dto';
import { UpdateRoomTypeDto } from './dto/update-room-type.dto';
import { RoomTypeRepository } from './room-type.repository';

@Injectable()
export class RoomTypeService {
  constructor(private readonly repo: RoomTypeRepository) {}

  async findAll() {
    return this.repo.findAll();
  }

  async findOne(id: number) {
    const roomType = await this.repo.findOne(id);
    if (!roomType) throw new NotFoundException(`RoomType #${id} not found`);
    return roomType;
  }

  async create(dto: CreateRoomTypeDto) {
    return this.repo.create(dto);
  }

  async update(id: number, dto: UpdateRoomTypeDto) {
    await this.findOne(id);
    return this.repo.update(id, dto);
  }

  async remove(id: number) {
    await this.findOne(id);

    const roomCount = await this.repo.countRooms(id);
    if (roomCount > 0) {
      throw new ConflictException(
        'Cannot delete: RoomType is in use by existing rooms',
      );
    }

    const flowRoomCount = await this.repo.countFlowRooms(id);
    if (flowRoomCount > 0) {
      throw new ConflictException(
        'Cannot delete: RoomType is referenced by existing flows',
      );
    }

    return this.repo.delete(id);
  }
}