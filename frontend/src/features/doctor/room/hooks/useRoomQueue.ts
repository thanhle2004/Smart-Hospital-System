// features/doctor/room/hooks/useRoomQueue.ts
'use client'

import { useState, useEffect, useCallback } from 'react'
import { doctorRoomService } from '../services/room.service'
import { useRoomSocket } from './useRoomSocket'
import type { VisitRoom } from '../types/room.type'

export function useRoomQueue(roomId: number) {
  const [waiting, setWaiting] = useState<VisitRoom[]>([])
  const [inProgress, setInProgress] = useState<VisitRoom[]>([])
  const [current, setCurrent] = useState<VisitRoom | null>(null)
  const [inProgressCount, setInProgressCount] = useState(0)
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchQueue = useCallback(async () => {
    setError(null)
    try {
      const data = await doctorRoomService.getQueue(roomId)
      setWaiting(data.waiting)
      setInProgress(data.inProgress)
      setCurrent(data.current)
      setInProgressCount(data.inProgressCount)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load queue')
    } finally {
      setLoading(false)
    }
  }, [roomId])

  useEffect(() => {
    fetchQueue()
  }, [fetchQueue])

  // Realtime: WebSocket updates queue
  useRoomSocket({
    roomId,
    onQueueUpdated: (payload) => {
      setWaiting(payload.waiting)
      setInProgress(payload.inProgress)
      setCurrent(payload.current)
      setInProgressCount(payload.inProgressCount)
    },
  })

  const callNext = useCallback(async () => {
    const next = waiting[0]
    if (!next) return
    setActionLoading(true)
    setError(null)
    try {
      await doctorRoomService.callPatient(next.id)
      // WebSocket updates state, no refetch needed
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to call next patient')
      throw err
    } finally {
      setActionLoading(false)
    }
  }, [waiting])

  const completeCurrent = useCallback(async (visitRoomId: number) => {
    setActionLoading(true)
    setError(null)
    try {
      await doctorRoomService.completePatient(visitRoomId)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to complete current patient')
      throw err
    } finally {
      setActionLoading(false)
    }
  }, [])

  const skipPatient = useCallback(async (visitRoomId: number) => {
    setActionLoading(true)
    setError(null)
    try {
      await doctorRoomService.skipPatient(visitRoomId)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to skip patient')
      throw err
    } finally {
      setActionLoading(false)
    }
  }, [])

  return {
    waiting,
    inProgress,
    current,
    inProgressCount,
    loading,
    actionLoading,
    error,
    callNext,
    completeCurrent,
    skipPatient,
    refetch: fetchQueue,
  }
}