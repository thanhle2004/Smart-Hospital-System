import { CreateRoomDto, Room, UpdateRoomDto } from "../types/room.type";
import { api } from '@/lib/axios';

export const roomService = {
  async getAll(): Promise<Room[]> {
    const response = await api.get<Room[]>('/room');
    return response.data;
  },

  async getOne(id: number): Promise<Room> {
    const response = await api.get<Room>(`/room/${id}`);
    return response.data;
  },

  async create(dto: CreateRoomDto): Promise<Room> {
    const response = await api.post<Room>('/room', dto);
    return response.data;
  },

  async update(id: number, dto: UpdateRoomDto): Promise<Room> {
    const response = await api.put<Room>(`/room/${id}`, dto);
    return response.data;
  },

  async remove(id: number): Promise<void> {
    await api.delete<void>(`/room/${id}`);
  },
};
