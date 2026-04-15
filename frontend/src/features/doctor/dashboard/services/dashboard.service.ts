// features/doctor/dashboard/services/dashboard.service.ts
import type { ActiveRoom, DoctorStats } from '../types/dashboard.type'

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

export const dashboardService = {
  getStats(): Promise<DoctorStats> {
    return request<DoctorStats>('/room/stats')
  },

  getActiveRooms(): Promise<ActiveRoom[]> {
    return request<ActiveRoom[]>('/room/active')
  },
}