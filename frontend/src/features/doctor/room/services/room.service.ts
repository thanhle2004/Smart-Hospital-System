// features/doctor/room/services/room.service.ts
import { api } from '@/lib/axios'
import type { ActiveRoom, RoomDetail, RoomDoctor, VisitRoom } from '../types/room.type'

export interface CurrentAssignment extends RoomDoctor {
  room: RoomDetail
}

export const doctorRoomService = {
  /** All rooms (for doctor shift selection) */
  async getAll(): Promise<RoomDetail[]> {
    const response = await api.get<RoomDetail[]>('/room')
    return response.data
  },

  /** Room details + active doctors */
  async getOne(id: number): Promise<RoomDetail> {
    const response = await api.get<RoomDetail>(`/room/${id}`)
    return response.data
  },

  /** Active doctors in this room */
  async getActiveDoctors(roomId: number): Promise<RoomDoctor[]> {
    const response = await api.get<RoomDoctor[]>(`/room/${roomId}/doctors`)
    return response.data
  },

  /** Queue: { waiting, inProgress, current } */
  async getQueue(roomId: number): Promise<{ waiting: VisitRoom[]; inProgress: VisitRoom[]; current: VisitRoom | null; inProgressCount: number }> {
    const response = await api.get<{ waiting: VisitRoom[]; inProgress: VisitRoom[]; current: VisitRoom | null; inProgressCount: number }>(
      `/room/${roomId}/queue`,
    )
    return response.data
  },

  /** Doctor check-in to room */
  async checkIn(roomId: number): Promise<RoomDoctor> {
    const response = await api.post<RoomDoctor>(`/room/${roomId}/check-in`)
    return response.data
  },

  /** Doctor check-out from room */
  async checkOut(roomId: number): Promise<void> {
    await api.post<void>(`/room/${roomId}/check-out`)
  },

  /** Doctor current active room */
  async getCurrentAssignment(): Promise<CurrentAssignment | null> {
    const response = await api.get<CurrentAssignment | null>('/room/current-assignment')
    return response.data
  },

  /** Call next patient (WAITING -> IN_PROGRESS) */
  async callPatient(visitRoomId: number): Promise<VisitRoom> {
    const response = await api.post<VisitRoom>(`/visit/visit-room/${visitRoomId}/call`)
    return response.data
  },

  /** Complete patient visit (IN_PROGRESS -> COMPLETED) */
  async completePatient(visitRoomId: number): Promise<VisitRoom> {
    const response = await api.post<VisitRoom>(`/visit/visit-room/${visitRoomId}/complete`)
    return response.data
  },

  /** Skip patient */
  async skipPatient(visitRoomId: number): Promise<VisitRoom> {
    const response = await api.post<VisitRoom>(`/visit/visit-room/${visitRoomId}/skip`)
    return response.data
  },
}