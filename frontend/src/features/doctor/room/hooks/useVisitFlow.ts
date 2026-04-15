// features/doctor/room/hooks/useVisitFlow.ts
'use client'

import { useState, useEffect, useCallback } from 'react'
import { visitFlowService } from '../services/visit-flow.service'
import type { VisitFlow } from '../types/room.type'

export function useVisitFlow(visitId: string | null) {
  const [flows, setFlows] = useState<VisitFlow[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchFlow = useCallback(async () => {
    if (!visitId) return
    setLoading(true)
    setError(null)
    try {
      const data = await visitFlowService.getByVisit(visitId)
      setFlows(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load visit flow')
    } finally {
      setLoading(false)
    }
  }, [visitId])

  useEffect(() => {
    fetchFlow()
  }, [fetchFlow])

  const addRoom = useCallback(async (roomTypeId: number, requiredVisitFlowIds: number[] = []) => {
    if (!visitId) return
    setError(null)
    try {
      await visitFlowService.addRoom(visitId, roomTypeId, requiredVisitFlowIds)
      await fetchFlow()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add room to visit flow')
      throw err
    }
  }, [visitId, fetchFlow])

  const skipStep = useCallback(async (visitFlowId: number) => {
    setError(null)
    try {
      await visitFlowService.skipStep(visitFlowId)
      await fetchFlow()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to skip step')
      throw err
    }
  }, [fetchFlow])

  const unskipStep = useCallback(async (visitFlowId: number) => {
    setError(null)
    try {
      await visitFlowService.unskipStep(visitFlowId)
      await fetchFlow()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to unskip step')
      throw err
    }
  }, [fetchFlow])

  const skipAllExcept = useCallback(async (keepVisitFlowId: number) => {
    if (!visitId) return
    setError(null)
    try {
      await visitFlowService.skipAllExcept(visitId, keepVisitFlowId)
      await fetchFlow()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to skip other steps')
      throw err
    }
  }, [visitId, fetchFlow])

  const removeStep = useCallback(async (visitFlowId: number) => {
    setError(null)
    try {
      await visitFlowService.removeStep(visitFlowId)
      await fetchFlow()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove step')
      throw err
    }
  }, [fetchFlow])

  return {
    flows,
    loading,
    error,
    addRoom,
    skipStep,
    unskipStep,
    skipAllExcept,
    removeStep,
    refetch: fetchFlow,
  }
}