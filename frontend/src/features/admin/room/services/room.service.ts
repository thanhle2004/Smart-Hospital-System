import { CreateRoomDto, Room, UpdateRoomDto } from "../types/room.type";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:5000";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    credentials: "include",
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({}));
    throw new Error(error?.message ?? `Request failed: ${res.status}`);
  }

  // 204 No Content
  if (res.status === 204) return undefined as T;
  return res.json();
}

export const roomService = {
  getAll(): Promise<Room[]> {
    return request<Room[]>("/room");
  },

  getOne(id: number): Promise<Room> {
    return request<Room>(`/room/${id}`);
  },

  create(dto: CreateRoomDto): Promise<Room> {
    return request<Room>("/room", {
      method: "POST",
      body: JSON.stringify(dto),
    });
  },

  update(id: number, dto: UpdateRoomDto): Promise<Room> {
    return request<Room>(`/room/${id}`, {
      method: "PUT",
      body: JSON.stringify(dto),
    });
  },

  remove(id: number): Promise<void> {
    return request<void>(`/room/${id}`, { method: "DELETE" });
  },
};
