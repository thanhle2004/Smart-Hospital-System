'use client'

import { useState, useEffect } from 'react'
import { visitFlowService } from '../services/visit-flow.service'

export interface RoomType {
  id: number
  name: string
}

export function useRoomTypes() {
  const [roomTypes, setRoomTypes] = useState<RoomType[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchRoomTypes = async () => {
      setLoading(true)
      setError(null)
      try {
        const data = await visitFlowService.getAllRoomTypes()
        setRoomTypes(data)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load room types')
      } finally {
        setLoading(false)
      }
    }

    fetchRoomTypes()
  }, [])

  return { roomTypes, loading, error }
}
