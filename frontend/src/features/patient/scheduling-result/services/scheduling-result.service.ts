const API_BASE = 'http://localhost:5000'

export async function fetchVisitById(id: string) {
  const res = await fetch(
    `${API_BASE}/visit/${id}`,
    { 
      credentials: 'include',
    },
  )

  if (!res.ok) {
    throw new Error('Failed to fetch visit')
  }

  return res.json()
}

export async function completeRoom(visitRoomId: number) {
  await fetch(
    `${API_BASE}/visit/visit-room/${visitRoomId}/complete`,
    { method: 'POST' }
  )
}