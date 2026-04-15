'use client'

import { useEffect, useState } from 'react'
import { useSearchParams } from 'next/navigation'

export interface ActiveVisit {
  id: string
  patientId: string
  flowId: number
  status: string
}

export function useActiveVisit(patientIdOverride?: string | null) {
  const searchParams = useSearchParams()
  const patientId = patientIdOverride ?? searchParams.get('patientId')

  const [activeVisit, setActiveVisit] = useState<ActiveVisit | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchActiveVisit = async () => {
      try {
        setLoading(true)
        setError(null)

        if (!patientId) {
          setActiveVisit(null)
          setLoading(false)
          return
        }

        // Fetch visits for this patient
        const res = await fetch(
          `http://localhost:5000/visit?patientId=${patientId}`,
          {
            credentials: 'include',
          }
        )

        if (!res.ok) {
          setActiveVisit(null)
          setLoading(false)
          return
        }

        const visits: ActiveVisit[] = await res.json()

        // Find the first active visit (WAITING or IN_PROGRESS status)
        const active = visits.find(v => v.status === 'WAITING' || v.status === 'IN_PROGRESS')

        setActiveVisit(active || null)
      } catch (err) {
        console.error('Failed to fetch active visits:', err)
        setError(err instanceof Error ? err.message : 'Failed to check active visits')
      } finally {
        setLoading(false)
      }
    }

    fetchActiveVisit()
  }, [patientId])

  return { activeVisit, loading, error }
}
