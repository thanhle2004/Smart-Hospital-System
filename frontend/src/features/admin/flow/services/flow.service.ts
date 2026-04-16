import type {
  Flow,
  FlowSimple,
  CreateFlowDto,
  UpdateFlowDto,
  UpsertFlowRoomsDto,
  FlowRoomItemDto,
  FlowRoomDependencyItemDto,
} from '../types/flow.type';
import { api } from '@/lib/axios';

const FLOW_PATH = '/admin/flows';

// ─── Flow CRUD ────────────────────────────────────────────────────────────────

export const flowService = {
  /** Get all flows (with rooms and dependencies) */
  async findAll(): Promise<Flow[]> {
    const response = await api.get<Flow[]>(FLOW_PATH);
    return response.data;
  },

  /** Get simple list (id + name) */
  async findAllSimple(): Promise<FlowSimple[]> {
    const response = await api.get<FlowSimple[]>(`${FLOW_PATH}/simple`);
    return response.data;
  },

  /** Get one flow detail */
  async findOne(id: number): Promise<Flow> {
    const response = await api.get<Flow>(`${FLOW_PATH}/${id}`);
    return response.data;
  },

  /** Create flow */
  async create(dto: CreateFlowDto): Promise<Flow> {
    const response = await api.post<Flow>(FLOW_PATH, dto);
    return response.data;
  },

  /** Update flow name */
  async update(id: number, dto: UpdateFlowDto): Promise<Flow> {
    const response = await api.patch<Flow>(`${FLOW_PATH}/${id}`, dto);
    return response.data;
  },

  /** Delete flow */
  async remove(id: number): Promise<void> {
    await api.delete<void>(`${FLOW_PATH}/${id}`);
  },

  // ─── Rooms ───────────────────────────────────────────────────────────────────

  /** Replace all rooms and dependencies */
  async upsertRooms(id: number, dto: UpsertFlowRoomsDto): Promise<Flow> {
    const response = await api.patch<Flow>(`${FLOW_PATH}/${id}/rooms`, dto);
    return response.data;
  },

  /** Add one room to flow */
  async addRoom(id: number, dto: FlowRoomItemDto): Promise<Flow> {
    const response = await api.post<Flow>(`${FLOW_PATH}/${id}/rooms`, dto);
    return response.data;
  },

  /** Remove one room from flow */
  async removeRoom(id: number, roomTypeId: number): Promise<Flow> {
    const response = await api.delete<Flow>(`${FLOW_PATH}/${id}/rooms/${roomTypeId}`);
    return response.data;
  },

  // ─── Dependencies ─────────────────────────────────────────────────────────────

  /** Add dependency */
  async addDependency(id: number, dto: FlowRoomDependencyItemDto): Promise<Flow> {
    const response = await api.post<Flow>(`${FLOW_PATH}/${id}/dependencies`, dto);
    return response.data;
  },

  /** Remove dependency */
  async removeDependency(id: number, dto: FlowRoomDependencyItemDto): Promise<void> {
    await api.delete<void>(`${FLOW_PATH}/${id}/dependencies`, {
      data: dto,
    });
  },
};