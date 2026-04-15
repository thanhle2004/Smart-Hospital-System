// features/doctor/room/components/DoctorList.tsx
'use client'

import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { UserPlus, LogOut, Stethoscope } from 'lucide-react'
import { useDoctorCheckin } from '../hooks/useDoctorCheckin'
import { toast } from 'sonner'
import type { RoomDoctor } from '../types/room.type'

// Format check-in time
function formatCheckinTime(startTime: string): string {
  return new Date(startTime).toLocaleTimeString('vi-VN', {
    hour: '2-digit',
    minute: '2-digit',
  })
}

function getInitials(name: string | null, email: string): string {
  const source = name ?? email
  return source
    .split(' ')
    .map((w) => w[0])
    .filter(Boolean)
    .slice(-2)
    .join('')
    .toUpperCase()
}

interface DoctorListProps {
  roomId: number
  currentUserId: string
  onCapacityChange?: () => void
}

function DoctorItem({ assignment }: { assignment: RoomDoctor }) {
  const name = assignment.doctor?.profile?.fullName ?? null
  const email = assignment.doctor?.email?? 'unknown@gmail.com'
  const initials = getInitials(name, email)

  return (
    <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50">
      <div className="relative flex-shrink-0">
        <div className="w-9 h-9 rounded-full bg-primary/10 flex items-center justify-center">
          <span className="text-xs font-bold text-primary">{initials}</span>
        </div>
        <span className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full bg-emerald-500 border-2 border-background" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium truncate">{name ?? email}</p>
        <p className="text-xs text-muted-foreground">
          Entered at {formatCheckinTime(assignment.startTime)}
        </p>
      </div>
    </div>
  )
}

export function DoctorList({
  roomId,
  currentUserId,
  onCapacityChange,
}: DoctorListProps) {
  const { doctors, loading, checkIn, checkOut } = useDoctorCheckin(roomId)
  const [actionLoading, setActionLoading] = useState(false)

  const isCurrentUserIn = doctors.some(
    (d) => d.doctorId === currentUserId && d.isActive,
  )

  const handleCheckIn = async () => {
    setActionLoading(true)
    try {
      await checkIn()
      toast.success('Entered the room')
      onCapacityChange?.()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Cannot enter the room')
    } finally {
      setActionLoading(false)
    }
  }

  const handleCheckOut = async () => {
    setActionLoading(true)
    try {
      await checkOut()
      toast.success('Left the room')
      onCapacityChange?.()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Cannot leave the room')
    } finally {
      setActionLoading(false)
    }
  }

  return (
    <Card className="gap-0">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-2">
            <Stethoscope className="w-4 h-4 text-primary" />
            Doctors on Duty
            <Badge variant="secondary">{doctors.length}</Badge>
          </CardTitle>
        </div>
      </CardHeader>

      <CardContent className="space-y-1.5 pt-0">
        {loading ? (
          <>
            <Skeleton className="h-14 w-full rounded-lg" />
            <Skeleton className="h-14 w-full rounded-lg" />
          </>
        ) : doctors.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-3">
            No doctors on duty
          </p>
        ) : (
          doctors.map((a) => <DoctorItem key={a.id} assignment={a} />)
        )}
      </CardContent>
    </Card>
  )
}