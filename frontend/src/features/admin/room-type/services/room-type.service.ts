import { CreateRoomTypeDto, RoomType, UpdateRoomTypeDto } from "../types/room-type.type";
import { api } from '@/lib/axios';

export const roomTypeService = {
  async getAll(): Promise<RoomType[]> {
    const response = await api.get<RoomType[]>('/admin/room-types');
    return response.data;
  },

  async getOne(id: number): Promise<RoomType> {
    const response = await api.get<RoomType>(`/admin/room-types/${id}`);
    return response.data;
  },

  async create(dto: CreateRoomTypeDto): Promise<RoomType> {
    const response = await api.post<RoomType>('/admin/room-types', dto);
    return response.data;
  },

  async update(id: number, dto: UpdateRoomTypeDto): Promise<RoomType> {
    const response = await api.patch<RoomType>(`/admin/room-types/${id}`, dto);
    return response.data;
  },

  async remove(id: number): Promise<void> {
    await api.delete<void>(`/admin/room-types/${id}`);
  },
};