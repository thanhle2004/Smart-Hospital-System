'use client'

import { useEffect, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import { fetchVisitById } from '../services/scheduling-result.service'
import { Visit } from '../types/scheduling-result.type'

export function useSchedulingResult() {

  const searchParams = useSearchParams()
  const visitId = searchParams.get('visitId')

  const [visit, setVisit] = useState<Visit | null>(null)
  const [error, setError] = useState<string | null>(null)

  const currentRoom = visit?.visitRooms.find(
    vr => vr.status === 'WAITING' || vr.status === 'IN_PROGRESS'
  )

  useEffect(() => {
    if (!visitId) return

    let cancelled = false

    const load = async () => {
      try {
        const data = await fetchVisitById(visitId)
        if (!cancelled) {
          setVisit(data)
        }
      } catch (e) {
        if (!cancelled) {
          setError('Failed to load visit')
        }
      }
    }

    load()
    const interval = setInterval(load, 4000)

    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [visitId])

  return {
    visit,
    currentRoom,
    error,
  }
}