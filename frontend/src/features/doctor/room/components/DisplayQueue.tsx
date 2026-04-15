// features/doctor/room/components/DisplayQueue.tsx
'use client'

import { useEffect, useState } from 'react'
import { doctorRoomService } from '../services/room.service'
import { useRoomSocket } from '../hooks/useRoomSocket'
import type { VisitRoom } from '../types/room.type'

function useClock() {
  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return time
}

interface DisplayQueueProps {
  roomId: number
  roomName: string
}

export function DisplayQueue({ roomId, roomName }: DisplayQueueProps) {
  const [waiting, setWaiting] = useState<VisitRoom[]>([])
  const [current, setCurrent] = useState<VisitRoom | null>(null)
  const time = useClock()

  useEffect(() => {
    doctorRoomService.getQueue(roomId).then((data) => {
      setWaiting(data.waiting)
      setCurrent(data.current)
    })
  }, [roomId])

  useRoomSocket({
    roomId,
    onQueueUpdated: (payload) => {
      setWaiting(payload.waiting)
      setCurrent(payload.current)
    },
  })

  const timeStr = time.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })

  const dateStr = time.toLocaleDateString('en-US', {
    weekday: 'long',
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  })

  return (
    <div className="min-h-screen bg-slate-900 text-white flex flex-col select-none">
      {/* Header */}
      <header className="flex items-center justify-between px-10 py-6 border-b border-white/10 flex-shrink-0">
        <div>
          <p className="text-slate-400 text-xs font-semibold uppercase tracking-widest">
            Room:
          </p>
          <h1 className="text-3xl font-bold mt-1">{roomName}</h1>
        </div>
        <div className="text-right">
          <p className="text-4xl font-mono font-bold tabular-nums">{timeStr}</p>
          <p className="text-slate-400 text-sm mt-1 capitalize">{dateStr}</p>
        </div>
      </header>

      <div className="flex-1 grid grid-cols-5 min-h-0">
        {/* NOW SERVING */}
        <div className="col-span-2 flex flex-col bg-emerald-900/30 border-r border-white/10 p-10">
          <p className="text-emerald-400 text-xs font-bold uppercase tracking-widest mb-8">
            Now Serving
          </p>

          {current ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-5">
              {/* Avatar */}
              <div className="w-24 h-24 rounded-full bg-emerald-500/20 border-4 border-emerald-500 flex items-center justify-center">
                <span className="text-4xl font-bold text-emerald-300">
                  {current.visit.patient.name.split(' ').pop()?.[0]?.toUpperCase() ?? '?'}
                </span>
              </div>

              <div className="text-center space-y-2">
                <p className="text-4xl font-bold leading-tight">
                  {current.visit.patient.name}
                </p>
                <p className="text-emerald-300 text-xl">
                  Year of Birth: {current.visit.patient.yearOfBirth}
                </p>
                <span className="inline-block px-4 py-1.5 bg-emerald-500/20 rounded-full text-emerald-300 text-sm font-medium">
                  {current.visit.patient.patientType.name}
                </span>
              </div>

              <div className="flex items-center gap-2 mt-2">
                <span className="relative flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500" />
                </span>
                <span className="text-emerald-400 text-sm">Currently Being Examined</span>
              </div>
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center">
              <p className="text-slate-500 text-xl">Room is currently empty</p>
            </div>
          )}
        </div>

        {/* WAITING LIST */}
        <div className="col-span-3 flex flex-col p-10 overflow-hidden">
          <div className="flex items-center justify-between mb-6 flex-shrink-0">
            <p className="text-slate-400 text-xs font-bold uppercase tracking-widest">
              Waiting List
            </p>
            <span className="text-slate-500 text-sm">
              {waiting.length} patients waiting
            </span>
          </div>

          {waiting.length === 0 ? (
            <div className="flex-1 flex items-center justify-center">
              <p className="text-slate-600 text-xl">No patients waiting</p>
            </div>
          ) : (
            <div className="space-y-3 overflow-y-auto flex-1">
              {waiting.map((vr, index) => {
                const patient = vr.visit.patient
                const isNext = index === 0

                return (
                  <div
                    key={vr.id}
                    className={`flex items-center gap-5 p-5 rounded-2xl border transition-all ${
                      isNext
                        ? 'bg-amber-500/10 border-amber-500/30'
                        : 'bg-white/5 border-white/5'
                    }`}
                  >
                    {/* STT */}
                    <div
                      className={`w-12 h-12 rounded-full flex items-center justify-center font-bold text-xl flex-shrink-0 ${
                        isNext
                          ? 'bg-amber-500 text-white'
                          : 'bg-white/10 text-slate-400'
                      }`}
                    >
                      {index + 1}
                    </div>

                    {/* Patient info */}
                    <div className="flex-1 min-w-0">
                      <p
                        className={`text-xl font-bold truncate ${
                          isNext ? 'text-amber-300' : 'text-white'
                        }`}
                      >
                        {patient.name}
                      </p>
                      <p className="text-slate-400 text-sm mt-0.5">
                        Year of Birth: {patient.yearOfBirth}
                        &nbsp;•&nbsp;{patient.patientType.name}
                      </p>
                    </div>

                    {isNext && (
                      <span className="text-amber-400 text-sm font-medium flex-shrink-0">
                        Next ↑
                      </span>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}