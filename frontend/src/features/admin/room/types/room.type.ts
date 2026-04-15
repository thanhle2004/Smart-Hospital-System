export interface RoomType {
  id: number;
  name: string;
  description?: string | null;
  avgProcessTime: number;
  defaultCapacity: number;
}

export interface Room {
  id: number;
  name: string;
  roomNumber: number;
  capacity: number;
  roomTypeId: number | null;
  roomType: RoomType | null;
  avgProcessTime: number;
}

export interface CreateRoomDto {
  name: string;
  roomNumber: number;
  roomTypeId?: number | null;
  avgProcessTime: number;
}

export type UpdateRoomDto = Partial<CreateRoomDto>;

export interface RoomFormValues {
  name: string;
  roomNumber: string;
  roomTypeId: string;
  avgProcessTime: string;
}