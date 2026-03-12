'use client'

import { useEffect, useState } from 'react'
import { useSearchParams } from 'next/navigation'

const API_BASE = 'http://localhost:5000'

export default function SchedulingResultPage() {

  const searchParams = useSearchParams()
  const visitId = searchParams.get('visitId')

  const [visit, setVisit] = useState<any>(null)

  const fetchVisit = async () => {
    if (!visitId) return

    const res = await fetch(`${API_BASE}/visit/${visitId}`)
    const data = await res.json()

    setVisit((prev: any) => {
      if (JSON.stringify(prev) === JSON.stringify(data)) {
        return prev
      }
      return data
    })
  }

  useEffect(() => {
    fetchVisit()

    const interval = setInterval(fetchVisit, 4000)

    return () => clearInterval(interval)
  }, [visitId])

  const currentRoom = visit?.visitRooms?.find(
    (vr: any) => vr.status === 'WAITING'
  )

  if (!visit) {
    return <div className="p-10">Loading...</div>
  }

  return (
    <div className="min-h-screen bg-gray-50 p-6">

      <div className="max-w-md mx-auto space-y-6">

        {/* TITLE */}

        <h1 className="text-xl font-bold text-blue-900">
          Visit Flow
        </h1>

        {/* CURRENT ROOM */}

        {currentRoom && (
          <div className="bg-blue-100 p-4 rounded-lg">

            <p className="text-sm text-gray-600">
              CURRENT ROOM
            </p>

            <h2 className="text-lg font-bold text-blue-800">
              {currentRoom.room.name} - Room {currentRoom.room.roomNumber}
            </h2>

          </div>
        )}

        {/* FLOW PROGRESS */}

        <div className="space-y-3">

          {visit.flow.flowRooms.map((fr: any) => {

            const vr = visit.visitRooms.find(
              (v: any) => v.room?.roomTypeId === fr.roomTypeId
            )

            let status = 'PENDING'

            if (vr?.status === 'COMPLETED') status = 'COMPLETED'
            if (vr?.status === 'WAITING') status = 'CURRENT'

            return (
              <div
                key={fr.id}
                className="bg-white p-4 rounded-lg border flex justify-between items-center"
              >

                <div>

                  <div className="font-medium">
                    {fr.roomType.name}
                  </div>

                  {vr && (
                    <div className="text-xs text-gray-500">
                      Room {vr.room.number}
                    </div>
                  )}

                </div>

                <span className="text-sm font-semibold">

                  {status === 'COMPLETED' && '✅ COMPLETED'}
                  {status === 'CURRENT' && '🟡 CURRENT'}
                  {status === 'PENDING' && '⚪ PENDING'}

                </span>

              </div>
            )
          })}

        </div>

        {/* TEST COMPLETE BUTTON */}

        {currentRoom && (

          <button
            onClick={async () => {

              await fetch(
                `${API_BASE}/visit/visit-room/${currentRoom.id}/complete`,
                { method: 'POST' }
              )

              await fetchVisit()

            }}
            className="w-full bg-green-600 text-white h-12 rounded-lg"
          >
            Complete Room (Test)
          </button>

        )}

      </div>

    </div>
  )
}