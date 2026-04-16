// features/doctor/dashboard/services/dashboard.service.ts
import { api } from '@/lib/axios'
import type { ActiveRoom, DoctorStats } from '../types/dashboard.type'

export const dashboardService = {
  async getStats(): Promise<DoctorStats> {
    const response = await api.get<DoctorStats>('/room/stats')
    return response.data
  },

  async getActiveRooms(): Promise<ActiveRoom[]> {
    const response = await api.get<ActiveRoom[]>('/room/active')
    return response.data
  },
}