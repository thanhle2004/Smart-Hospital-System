// features/doctor/dashboard/components/ActiveRoomsList.tsx
'use client'

import { useRouter } from 'next/navigation'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { DoorOpen, Users, ChevronRight, User, Circle } from 'lucide-react'
import type { ActiveRoom } from '../types/dashboard.type'

interface ActiveRoomsListProps {
  rooms: ActiveRoom[]
  loading: boolean
}

export function ActiveRoomsList({ rooms, loading }: ActiveRoomsListProps) {
  const router = useRouter()

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <DoorOpen className="w-4 h-4 text-primary" />
          Active Rooms
          <Badge variant="secondary">{rooms.length}</Badge>
        </CardTitle>
      </CardHeader>

      <CardContent className="p-0">
        {loading ? (
          <div className="p-6 space-y-3">
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-20 w-full rounded-lg" />
            ))}
          </div>
        ) : rooms.length === 0 ? (
          <div className="flex flex-col items-center py-12 text-muted-foreground">
            <DoorOpen className="w-10 h-10 mb-3 opacity-30" />
            <p className="text-sm">No active rooms available</p>
          </div>
        ) : (
          <div className="divide-y">
            {rooms.map(({ room, currentPatient, waitingCount }) => {
              const activeDoctors = room.roomAssignments.filter((a) => a.isActive)

              return (
                <div
                  key={room.id}
                  className="flex items-center gap-4 px-6 py-4 hover:bg-muted/40 transition-colors"
                >
                  <div className="flex-1 min-w-0">
                    {/* Room name + badges */}
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="font-semibold text-sm">{room.name}</span>
                      <Badge variant="outline" className="text-xs">
                        {room.roomType?.name ?? 'Unassigned'}
                      </Badge>
                      {currentPatient ? (
                        <Badge className="text-xs bg-emerald-500 hover:bg-emerald-500">
                          In Progress
                        </Badge>
                      ) : (
                        <Badge variant="secondary" className="text-xs">
                          Available
                        </Badge>
                      )}
                    </div>

                    {/* Doctors + waiting count */}
                    <div className="flex items-center gap-3 text-xs text-muted-foreground">
                      <div className="flex items-center gap-1">
                        <Users className="w-3 h-3" />
                        <span>{activeDoctors.length} doctors</span>
                      </div>
                      <span>•</span>
                      <div className="flex items-center gap-1">
                        <Circle className="w-3 h-3" />
                        <span>{waitingCount} waiting</span>
                      </div>
                    </div>

                    {/* Current patient */}
                    {currentPatient && (
                      <div className="flex items-center gap-1.5 mt-1 text-xs">
                        <User className="w-3 h-3 text-emerald-500" />
                        <span className="text-emerald-700 font-medium">
                          In Progress: {currentPatient.visit.patient.name}
                        </span>
                      </div>
                    )}
                  </div>

                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => router.push(`/doctor/room/${room.id}`)}
                    className="flex-shrink-0"
                  >
                    Enter Room
                    <ChevronRight className="w-3.5 h-3.5 ml-1" />
                  </Button>
                </div>
              )
            })}
          </div>
        )}
      </CardContent>
    </Card>
  )
}