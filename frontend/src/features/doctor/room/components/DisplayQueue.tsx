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
  const [inProgress, setInProgress] = useState<VisitRoom[]>([])
  const time = useClock()

  useEffect(() => {
    doctorRoomService.getQueue(roomId).then((data) => {
      setWaiting(data.waiting)
      setInProgress(data.inProgress)
    })
  }, [roomId])

  useRoomSocket({
    roomId,
    onQueueUpdated: (payload) => {
      setWaiting(payload.waiting)
      setInProgress(payload.inProgress)
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

          {inProgress.length > 0 ? (
            <div className="flex-1 overflow-y-auto space-y-4 pr-1">
              {inProgress.map((item, index) => (
                <div
                  key={item.id}
                  className="rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-5"
                >
                  <div className="flex items-start gap-4">
                    <div className="w-16 h-16 rounded-full bg-emerald-500/20 border-2 border-emerald-500 flex items-center justify-center flex-shrink-0">
                      <span className="text-2xl font-bold text-emerald-300">
                        {item.visit.patient.name.split(' ').pop()?.[0]?.toUpperCase() ?? '?'}
                      </span>
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-3">
                        <p className="text-2xl font-bold leading-tight truncate">
                          {item.visit.patient.name}
                        </p>
                        <span className="text-xs px-2.5 py-1 rounded-full bg-emerald-400/20 text-emerald-300 font-semibold flex-shrink-0">
                          Serving #{index + 1}
                        </span>
                      </div>

                      <p className="text-emerald-300 text-base mt-1">
                        Year of Birth: {item.visit.patient.yearOfBirth}
                      </p>

                      <div className="flex items-center gap-2 mt-2">
                        <span className="inline-block px-3 py-1 bg-emerald-500/20 rounded-full text-emerald-300 text-xs font-medium">
                          {item.visit.patient.patientType.name}
                        </span>
                        <span className="relative flex h-2.5 w-2.5">
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
                        </span>
                        <span className="text-emerald-400 text-xs">Currently Being Examined</span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}

              <div className="text-xs text-emerald-300/80 text-right">
                Now serving {inProgress.length} patient{inProgress.length > 1 ? 's' : ''}
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