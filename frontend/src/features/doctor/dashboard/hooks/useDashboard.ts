// features/doctor/dashboard/hooks/useDashboard.ts
'use client'

import { useState, useEffect, useCallback } from 'react'
import { dashboardService } from '../services/dashboard.service'
import type { ActiveRoom, DoctorStats } from '../types/dashboard.type'

export function useDashboard() {
  const [stats, setStats] = useState<DoctorStats | null>(null)
  const [activeRooms, setActiveRooms] = useState<ActiveRoom[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchAll = useCallback(async () => {
    setError(null)
    try {
      const [s, r] = await Promise.all([
        dashboardService.getStats(),
        dashboardService.getActiveRooms(),
      ])
      setStats(s)
      setActiveRooms(r)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchAll()
    // Fallback polling every 30s alongside WebSocket
    const id = setInterval(fetchAll, 30_000)
    return () => clearInterval(id)
  }, [fetchAll])

  return { stats, activeRooms, loading, error, refetch: fetchAll }
}