// features/doctor/room/services/visit-flow.service.ts
import type { VisitFlow } from '../types/room.type'

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

export const visitFlowService = {
  /** Get all visit-flow steps for a visit */
  getByVisit(visitId: string): Promise<VisitFlow[]> {
    return request<VisitFlow[]>(`/visit-flows/visit/${visitId}`)
  },

  /** Manually add roomType to flow */
  addRoom(
    visitId: string,
    roomTypeId: number,
    requiredVisitFlowIds: number[] = [],
  ): Promise<VisitFlow> {
    return request<VisitFlow>('/visit-flows', {
      method: 'POST',
      body: JSON.stringify({ visitId, roomTypeId, requiredVisitFlowIds }),
    })
  },

  /** Skip one step (uses visitFlowId) */
  skipStep(visitFlowId: number): Promise<VisitFlow> {
    return request<VisitFlow>(`/visit-flows/${visitFlowId}`, {
      method: 'PATCH',
      body: JSON.stringify({ isSkipped: true }),
    })
  },

  /** Unskip one step (uses visitFlowId) */
  unskipStep(visitFlowId: number): Promise<VisitFlow> {
    return request<VisitFlow>(`/visit-flows/${visitFlowId}/unskip`, {
      method: 'PATCH',
    })
  },

  /** Skip all skippable steps except the kept step */
  skipAllExcept(visitId: string, keepVisitFlowId: number): Promise<VisitFlow[]> {
    return request<VisitFlow[]>(`/visit-flows/visit/${visitId}/skip-all-except`, {
      method: 'POST',
      body: JSON.stringify({ keepVisitFlowId }),
    })
  },

  /** Remove manually added step (uses visitFlowId) */
  removeStep(visitFlowId: number): Promise<void> {
    return request<void>(`/visit-flows/${visitFlowId}`, { method: 'DELETE' })
  },

  /** Get all room types */
  getAllRoomTypes(): Promise<Array<{ id: number; name: string }>> {
    return request<Array<{ id: number; name: string }>>('/room-types')
  },
}