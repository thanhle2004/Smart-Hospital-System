// features/doctor/room/hooks/useRoomDetail.ts
'use client'

import { useState, useEffect, useCallback } from 'react'
import { doctorRoomService } from '../services/room.service'
import type { RoomDetail } from '../types/room.type'

export function useRoomDetail(roomId: number) {
  const [room, setRoom] = useState<RoomDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchRoom = useCallback(async () => {
    setError(null)
    try {
      const data = await doctorRoomService.getOne(roomId)
      setRoom(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load room details')
    } finally {
      setLoading(false)
    }
  }, [roomId])

  useEffect(() => {
    fetchRoom()
  }, [fetchRoom])

  return { room, loading, error, refetch: fetchRoom }
}