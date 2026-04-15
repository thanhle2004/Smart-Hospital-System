import { CreateRoomTypeDto, RoomType, UpdateRoomTypeDto } from "../types/room-type.type";

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

  if (res.status === 204) return undefined as T;
  return res.json();
}

export const roomTypeService = {
  getAll(): Promise<RoomType[]> {
    return request<RoomType[]>("/admin/room-types");
  },

  getOne(id: number): Promise<RoomType> {
    return request<RoomType>(`/admin/room-types/${id}`);
  },

  create(dto: CreateRoomTypeDto): Promise<RoomType> {
    return request<RoomType>("/admin/room-types", {
      method: "POST",
      body: JSON.stringify(dto),
    });
  },

  update(id: number, dto: UpdateRoomTypeDto): Promise<RoomType> {
    return request<RoomType>(`/admin/room-types/${id}`, {
      method: "PATCH",
      body: JSON.stringify(dto),
    });
  },

  remove(id: number): Promise<void> {
    return request<void>(`/admin/room-types/${id}`, {
      method: "DELETE",
    });
  },
};