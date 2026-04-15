// ─── Enums ────────────────────────────────────────────────────────────────────

export enum Role {
  ADMIN = 'ADMIN',
  DOCTOR = 'DOCTOR',
}

// ─── Base entities ─────────────────────────────────────────────────────────────

export interface RoomType {
  id: number;
  name: string;
  description?: string | null;
  avgProcessTime: number;
  defaultCapacity: number;
}

export interface FlowRoom {
  id: number;
  flowId: number;
  roomTypeId: number;
  defaultOrder: number;
  roomType: RoomType;
}

export interface FlowRoomDependency {
  flowId: number;
  roomTypeId: number;
  requiredRoomTypeId: number;
  roomType?: RoomType;
  requiredRoomType?: RoomType;
}

export interface Flow {
  id: number;
  name: string;
  flowRooms: FlowRoom[];
  dependencies: FlowRoomDependency[];
}

export interface FlowSimple {
  id: number;
  name: string;
}

// ─── DTOs ──────────────────────────────────────────────────────────────────────

export interface FlowRoomItemDto {
  roomTypeId: number;
  defaultOrder: number;
}

export interface FlowRoomDependencyItemDto {
  roomTypeId: number;
  requiredRoomTypeId: number;
}

export interface CreateFlowDto {
  name: string;
  rooms: FlowRoomItemDto[];
  dependencies?: FlowRoomDependencyItemDto[];
}

export interface FlowFormDto {
  name: string;
  rooms: FlowRoomItemDto[];
  dependencies: FlowRoomDependencyItemDto[];
}

export interface UpdateFlowDto {
  name?: string;
}

export interface UpsertFlowRoomsDto {
  rooms: FlowRoomItemDto[];
  dependencies?: FlowRoomDependencyItemDto[];
}

// ─── API Response wrappers ─────────────────────────────────────────────────────

export interface ApiResponse<T> {
  data: T;
  message?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
}