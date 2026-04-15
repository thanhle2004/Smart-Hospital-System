'use client'

import { useEffect, useState } from 'react'
import { Flow } from '../types/flow.type'
import { fetchFlows } from '../services/service-selection.service'

export function useFlows() {
  const [flows, setFlows] = useState<Flow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const load = async () => {
      try {
        const data = await fetchFlows()
        setFlows(data)
      } catch (e) {
        console.error(e)
        setError('Unable to load medical services. Please try again.')
      } finally {
        setLoading(false)
      }
    }

    load()
  }, [])

  return { flows, loading, error }
}