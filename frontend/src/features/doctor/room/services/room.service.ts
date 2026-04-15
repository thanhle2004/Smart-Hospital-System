// features/doctor/room/services/room.service.ts
import type { ActiveRoom, RoomDetail, RoomDoctor, VisitRoom } from '../types/room.type'

export interface CurrentAssignment extends RoomDoctor {
  room: RoomDetail
}

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:5000'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    credentials: 'include',
  })

  if (!res.ok) {
    const error = await res.json().catch(() => ({}))
    throw new Error(error?.message ?? `Request failed: ${res.status}`)
  }

  if (res.status === 204) return undefined as T
  return res.json()
}

export const doctorRoomService = {
  /** All rooms (for doctor shift selection) */
  getAll(): Promise<RoomDetail[]> {
    return request<RoomDetail[]>('/room')
  },

  /** Room details + active doctors */
  getOne(id: number): Promise<RoomDetail> {
    return request<RoomDetail>(`/room/${id}`)
  },

  /** Active doctors in this room */
  getActiveDoctors(roomId: number): Promise<RoomDoctor[]> {
    return request<RoomDoctor[]>(`/room/${roomId}/doctors`)
  },

  /** Queue: { waiting, current } */
  getQueue(roomId: number): Promise<{ waiting: VisitRoom[]; current: VisitRoom | null }> {
    return request(`/room/${roomId}/queue`)
  },

  /** Doctor check-in to room */
  checkIn(roomId: number): Promise<RoomDoctor> {
    return request<RoomDoctor>(`/room/${roomId}/check-in`, { method: 'POST' })
  },

  /** Doctor check-out from room */
  checkOut(roomId: number): Promise<void> {
    return request<void>(`/room/${roomId}/check-out`, { method: 'POST' })
  },

  /** Doctor current active room */
  getCurrentAssignment(): Promise<CurrentAssignment | null> {
    return request<CurrentAssignment | null>('/room/current-assignment')
  },

  /** Call next patient (WAITING -> IN_PROGRESS) */
  callPatient(visitRoomId: number): Promise<VisitRoom> {
    return request<VisitRoom>(`/visit/visit-room/${visitRoomId}/call`, {
      method: 'POST',
    })
  },

  /** Complete patient visit (IN_PROGRESS -> COMPLETED) */
  completePatient(visitRoomId: number): Promise<VisitRoom> {
    return request<VisitRoom>(`/visit/visit-room/${visitRoomId}/complete`, {
      method: 'POST',
    })
  },

  /** Skip patient */
  skipPatient(visitRoomId: number): Promise<VisitRoom> {
    return request<VisitRoom>(`/visit/visit-room/${visitRoomId}/skip`, {
      method: 'POST',
    })
  },
}