import type {
  Flow,
  FlowSimple,
  CreateFlowDto,
  UpdateFlowDto,
  UpsertFlowRoomsDto,
  FlowRoomItemDto,
  FlowRoomDependencyItemDto,
} from '../types/flow.type';

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:5000';
const FLOW_PATH = `${BASE_URL}/admin/flows`;

async function request<T>(
  url: string,
  options?: RequestInit,
): Promise<T> {
  const res = await fetch(url, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers ?? {}),
    },
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ message: res.statusText }));
    throw new Error(error?.message ?? 'Unable to process request');
  }

  // 204 No Content
  if (res.status === 204) return undefined as T;

  return res.json() as Promise<T>;
}

// ─── Flow CRUD ────────────────────────────────────────────────────────────────

export const flowService = {
  /** Get all flows (with rooms and dependencies) */
  findAll(): Promise<Flow[]> {
    return request<Flow[]>(FLOW_PATH);
  },

  /** Get simple list (id + name) */
  findAllSimple(): Promise<FlowSimple[]> {
    return request<FlowSimple[]>(`${FLOW_PATH}/simple`);
  },

  /** Get one flow detail */
  findOne(id: number): Promise<Flow> {
    return request<Flow>(`${FLOW_PATH}/${id}`);
  },

  /** Create flow */
  create(dto: CreateFlowDto): Promise<Flow> {
    return request<Flow>(FLOW_PATH, {
      method: 'POST',
      body: JSON.stringify(dto),
    });
  },

  /** Update flow name */
  update(id: number, dto: UpdateFlowDto): Promise<Flow> {
    return request<Flow>(`${FLOW_PATH}/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(dto),
    });
  },

  /** Delete flow */
  remove(id: number): Promise<void> {
    return request<void>(`${FLOW_PATH}/${id}`, { method: 'DELETE' });
  },

  // ─── Rooms ───────────────────────────────────────────────────────────────────

  /** Replace all rooms and dependencies */
  upsertRooms(id: number, dto: UpsertFlowRoomsDto): Promise<Flow> {
    return request<Flow>(`${FLOW_PATH}/${id}/rooms`, {
      method: 'PATCH',
      body: JSON.stringify(dto),
    });
  },

  /** Add one room to flow */
  addRoom(id: number, dto: FlowRoomItemDto): Promise<Flow> {
    return request<Flow>(`${FLOW_PATH}/${id}/rooms`, {
      method: 'POST',
      body: JSON.stringify(dto),
    });
  },

  /** Remove one room from flow */
  removeRoom(id: number, roomTypeId: number): Promise<Flow> {
    return request<Flow>(`${FLOW_PATH}/${id}/rooms/${roomTypeId}`, {
      method: 'DELETE',
    });
  },

  // ─── Dependencies ─────────────────────────────────────────────────────────────

  /** Add dependency */
  addDependency(id: number, dto: FlowRoomDependencyItemDto): Promise<Flow> {
    return request<Flow>(`${FLOW_PATH}/${id}/dependencies`, {
      method: 'POST',
      body: JSON.stringify(dto),
    });
  },

  /** Remove dependency */
  removeDependency(id: number, dto: FlowRoomDependencyItemDto): Promise<void> {
    return request<void>(`${FLOW_PATH}/${id}/dependencies`, {
      method: 'DELETE',
      body: JSON.stringify(dto),
    });
  },
};