export interface RoomType {
  id: number;
  name: string;
  description?: string | null;
  avgProcessTime: number; // minutes
  defaultCapacity: number;
  _count?: {
    rooms: number;
    flowRooms: number;
  };
}

export interface CreateRoomTypeDto {
  name: string;
  description?: string;
  avgProcessTime: number;
  defaultCapacity: number;
}

export type UpdateRoomTypeDto = Partial<CreateRoomTypeDto>;

export interface RoomTypeFormValues {
  name: string;
  description: string;
  avgProcessTime: string;
  defaultCapacity: string;
}