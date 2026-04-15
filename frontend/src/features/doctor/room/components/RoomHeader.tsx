// features/doctor/room/components/RoomHeader.tsx
'use client'

import { Badge } from '@/components/ui/badge'
import { Users, Clock, Hash } from 'lucide-react'
import type { RoomDetail } from '../types/room.type'
import { formatMinutesFromSeconds } from '@/lib/time'

interface RoomHeaderProps {
  room: RoomDetail
}

export function RoomHeader({ room }: RoomHeaderProps) {
  const activeDoctors = room.roomAssignments.filter((a) => a.isActive)

  return (
    <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-semibold tracking-widest uppercase text-muted-foreground">
            {room.roomType?.name ?? 'UNASSIGNED'}
          </span>
          <Badge variant={room.isActive ? 'default' : 'secondary'}>
            {room.isActive ? 'Open' : 'Closed'}
          </Badge>
        </div>
        <h1 className="text-2xl font-bold tracking-tight">{room.name}</h1>
      </div>

      <div className="flex flex-wrap gap-4 text-sm text-muted-foreground">
        <div className="flex items-center gap-1.5">
          <Hash className="w-4 h-4" />
          <span>Room {room.roomNumber}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Users className="w-4 h-4" />
          <span>
            Capacity:{' '}
            <span className="font-semibold text-foreground">{room.capacity}</span>
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <Clock className="w-4 h-4" />
          <span>~{formatMinutesFromSeconds(room.avgProcessTime)} minutes/patient</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-emerald-500 inline-block" />
          <span>
            <span className="font-semibold text-emerald-600">
              {activeDoctors.length}
            </span>{' '}
            doctors on duty
          </span>
        </div>
      </div>
    </div>
  )
}