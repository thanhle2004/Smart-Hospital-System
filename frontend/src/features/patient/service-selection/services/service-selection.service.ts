const API_BASE = 'http://localhost:5000'

export async function fetchFlows() {
  const res = await fetch(`${API_BASE}/flows/simple`, {
    credentials: 'include',
  })
  if (!res.ok) throw new Error('Failed to fetch flows')
  return res.json()
}

export async function checkIn(patientId: string, flowId: number) {
  try {
    const res = await fetch(`${API_BASE}/visit/check-in`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ patientId, flowId }),
    })

    console.log('Check-in Response Status:', res.status)

    if (!res.ok) {
      const contentType = res.headers.get('content-type')
      let errorMessage = 'Check-in failed'

      if (contentType && contentType.includes('application/json')) {
        try {
          const errorData = await res.json()
          console.log('Error Response:', errorData)
          errorMessage = errorData?.message || errorData?.error || 'Check-in failed'
        } catch (e) {
          console.error('Failed to parse error JSON:', e)
          errorMessage = `Check-in failed (${res.status}: ${res.statusText})`
        }
      } else {
        const text = await res.text()
        console.log('Error Response Text:', text)
        errorMessage = `Check-in failed (${res.status}: ${res.statusText})`
      }

      throw new Error(errorMessage)
    }

    const data = await res.json()
    console.log('Check-in Success:', data)
    return data
  } catch (error) {
    console.error('Check-in Error:', error)
    throw error
  }
}