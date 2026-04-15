// features/doctor/room/hooks/useDoctorCheckin.ts
'use client'

import { useState, useEffect, useCallback } from 'react'
import { doctorRoomService } from '../services/room.service'
import { useRoomSocket } from './useRoomSocket'
import type { RoomDoctor } from '../types/room.type'

export function useDoctorCheckin(roomId: number) {
  const [doctors, setDoctors] = useState<RoomDoctor[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchDoctors = useCallback(async () => {
    setError(null)
    try {
      const data = await doctorRoomService.getActiveDoctors(roomId)
      setDoctors(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load doctors')
    } finally {
      setLoading(false)
    }
  }, [roomId])

  useEffect(() => {
    fetchDoctors()
  }, [fetchDoctors])

  // Realtime: WebSocket updates the doctor list
  useRoomSocket({
    roomId,
    onDoctorsUpdated: (payload) => {
      setDoctors(payload.doctors)
    },
  })

  const checkIn = useCallback(async () => {
    setError(null)
    try {
      await doctorRoomService.checkIn(roomId)
      // WebSocket updates this state
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to check-in')
      throw err
    }
  }, [roomId])

  const checkOut = useCallback(async () => {
    setError(null)
    try {
      await doctorRoomService.checkOut(roomId)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to check-out')
      throw err
    }
  }, [roomId])

  return { doctors, loading, error, checkIn, checkOut }
}