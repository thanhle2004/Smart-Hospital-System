// features/doctor/room/services/visit-flow.service.ts
import { api } from '@/lib/axios'
import type { VisitFlow } from '../types/room.type'

export const visitFlowService = {
  /** Get all visit-flow steps for a visit */
  async getByVisit(visitId: string): Promise<VisitFlow[]> {
    const response = await api.get<VisitFlow[]>(`/visit-flows/visit/${visitId}`)
    return response.data
  },

  /** Manually add roomType to flow */
  addRoom(
    visitId: string,
    roomTypeId: number,
    requiredVisitFlowIds: number[] = [],
  ): Promise<VisitFlow> {
    return api
      .post<VisitFlow>('/visit-flows', { visitId, roomTypeId, requiredVisitFlowIds })
      .then((response) => response.data)
  },

  /** Skip one step (uses visitFlowId) */
  async skipStep(visitFlowId: number): Promise<VisitFlow> {
    const response = await api.patch<VisitFlow>(`/visit-flows/${visitFlowId}`, { isSkipped: true })
    return response.data
  },

  /** Unskip one step (uses visitFlowId) */
  async unskipStep(visitFlowId: number): Promise<VisitFlow> {
    const response = await api.patch<VisitFlow>(`/visit-flows/${visitFlowId}/unskip`)
    return response.data
  },

  /** Skip all skippable steps except the kept step */
  async skipAllExcept(visitId: string, keepVisitFlowId: number): Promise<VisitFlow[]> {
    const response = await api.post<VisitFlow[]>(`/visit-flows/visit/${visitId}/skip-all-except`, {
      keepVisitFlowId,
    })
    return response.data
  },

  /** Remove manually added step (uses visitFlowId) */
  async removeStep(visitFlowId: number): Promise<void> {
    await api.delete<void>(`/visit-flows/${visitFlowId}`)
  },

  /** Get all room types */
  async getAllRoomTypes(): Promise<Array<{ id: number; name: string }>> {
    const response = await api.get<Array<{ id: number; name: string }>>('/room-types')
    return response.data
  },
}