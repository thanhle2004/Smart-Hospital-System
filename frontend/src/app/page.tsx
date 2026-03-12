'use client'

import { useEffect, useState } from 'react'

const API_BASE = 'http://localhost:5000'

interface Room {
  id: number
  name: string
  roomNumber: number
  avgProcessTime: number
  queueLength: number
  estimatedWaitingTime: number
}

interface RoomType {
  id: number
  name: string
  rooms: Room[]
}

export default function TestPage() {
  const [roomTypes, setRoomTypes] = useState<RoomType[]>([])
  const [creating, setCreating] = useState(false)
  const [counter, setCounter] = useState(1)

  const fetchRooms = async () => {
    try {
      const res = await fetch(`${API_BASE}/room/dashboard`)
      const data = await res.json()
      setRoomTypes(data)
    } catch (err) {
      console.error(err)
    }
  }

  // load lần đầu
  useEffect(() => {
    fetchRooms()
  }, [])

  const createPatientAndCheckin = async () => {
    const randomPhone = '09' + Math.floor(Math.random() * 100000000)
    try {
      setCreating(true)

      const patientRes = await fetch(`${API_BASE}/patient`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: `Test Patient ${counter}`,
          phone: randomPhone,
          patientTypeId: 1,
        }),
      })

      const patient = await patientRes.json()
      console.log("PATIENT RESPONSE:", patient)

      await fetch(`${API_BASE}/visit/check-in`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          patientId: patient.id,
          flowId: 4,
          age: 30,
        }),
      })

      setCounter((prev) => prev + 1)

      // reload dashboard sau khi checkin
      await fetchRooms()

    } catch (err) {
      console.error('Create patient error:', err)
    } finally {
      setCreating(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-100 p-10">
      <div className="max-w-6xl mx-auto">

        <h1 className="text-3xl font-bold mb-8">
          Hospital Scheduling Test Dashboard
        </h1>

        <button
          onClick={createPatientAndCheckin}
          disabled={creating}
          className="mb-10 px-6 py-3 bg-black text-white rounded-xl hover:opacity-80 disabled:opacity-50"
        >
          {creating ? 'Processing...' : 'Create Patient + Check-in'}
        </button>

        <div className="space-y-10">
          {roomTypes.map((type) => (
            <div key={type.id}>

              <h2 className="text-2xl font-bold mb-4">
                {type.name}
              </h2>

              <div className="grid md:grid-cols-3 gap-6">
                {type.rooms.map((room) => (
                  <div
                    key={room.id}
                    className="bg-white rounded-2xl shadow-md p-6 border"
                  >
                    <h3 className="text-xl font-semibold">
                      {room.name}
                    </h3>

                    <p className="text-sm text-gray-500">
                      Room #{room.roomNumber}
                    </p>

                    <div className="mt-4 space-y-1 text-sm">

                      <p>
                        Avg Process:
                        <span className="font-semibold ml-1">
                          {room.avgProcessTime} phút
                        </span>
                      </p>

                      <p>
                        Queue:
                        <span className="font-bold ml-1">
                          {room.queueLength}
                        </span>
                      </p>

                      <p>
                        Estimated Wait:
                        <span className="font-bold text-blue-600 ml-1">
                          {room.estimatedWaitingTime} phút
                        </span>
                      </p>

                    </div>
                  </div>
                ))}
              </div>

            </div>
          ))}
        </div>

      </div>
    </div>
  )
}