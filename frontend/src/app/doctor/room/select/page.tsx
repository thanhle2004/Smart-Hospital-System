// app/doctor/room/select/page.tsx
'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { CurrentAssignment, doctorRoomService } from '@/features/doctor/room/services/room.service'
import { authService } from '@/features/auth/services/auth.service'
import type { RoomDetail } from '@/features/doctor/room/types/room.type'
import type { MeResponse } from '@/features/auth/types/auth.type'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  DoorOpen,
  Search,
  Users,
  Clock,
  Hash,
  Loader2,
  Stethoscope,
} from 'lucide-react'
import { toast } from 'sonner'
import { formatMinutesFromSeconds } from '@/lib/time'

export default function RoomSelectPage() {
  const router = useRouter()
  const [user, setUser] = useState<MeResponse | null>(null)
  const [rooms, setRooms] = useState<RoomDetail[]>([])
  const [loading, setLoading] = useState(true)
  const [checkingIn, setCheckingIn] = useState<number | null>(null)
  const [checkingOutCurrent, setCheckingOutCurrent] = useState(false)
  const [currentAssignment, setCurrentAssignment] = useState<CurrentAssignment | null>(null)
  const [showActiveRoomDialog, setShowActiveRoomDialog] = useState(false)
  const [search, setSearch] = useState('')

  useEffect(() => {
    authService.me()
      .then(setUser)
      .catch(() => router.push('/login'))
  }, [router])

  useEffect(() => {
    doctorRoomService
      .getAll()
      .then(setRooms)
      .catch(() => toast.error('Cannot load room list'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    doctorRoomService
      .getCurrentAssignment()
      .then((assignment) => {
        setCurrentAssignment(assignment)
        setShowActiveRoomDialog(Boolean(assignment))
      })
      .catch(() => {
        setCurrentAssignment(null)
      })
  }, [])

  const handleSelectRoom = async (room: RoomDetail) => {
    if (currentAssignment) {
      setShowActiveRoomDialog(true)
      return
    }

    setCheckingIn(room.id)
    try {
      await doctorRoomService.checkIn(room.id)
      toast.success(`You have checked into ${room.name}`)
      router.push(`/doctor/room/${room.id}`)
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : 'Cannot check-in into this room at this time',
      )
    } finally {
      setCheckingIn(null)
    }
  }

  const handleGoBackToCurrentRoom = () => {
    if (!currentAssignment) return
    router.push(`/doctor/room/${currentAssignment.roomId}`)
  }

  const handleCheckOutCurrentRoom = async () => {
    if (!currentAssignment) return

    setCheckingOutCurrent(true)
    try {
      await doctorRoomService.checkOut(currentAssignment.roomId)
      toast.success('You have been checked out of your current room')
      setCurrentAssignment(null)
      setShowActiveRoomDialog(false)

      const refreshedRooms = await doctorRoomService.getAll()
      setRooms(refreshedRooms)
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : 'Cannot check out of current room at this time',
      )
    } finally {
      setCheckingOutCurrent(false)
    }
  }

  const filtered = rooms.filter(
    (r) =>
      r.isActive &&
      Boolean(r.roomType) &&
      (r.name.toLowerCase().includes(search.toLowerCase()) ||
        (r.roomType?.name ?? '').toLowerCase().includes(search.toLowerCase()) ||
        String(r.roomNumber).includes(search)),
  )

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Top bar */}
      <header className="bg-white border-b sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
              <Stethoscope className="w-4 h-4 text-primary-foreground" />
            </div>
            <div>
              <p className="text-sm font-semibold leading-none">
                {user?.profile?.fullName ?? user?.email ?? '...'}
              </p>
              <p className="text-xs text-muted-foreground mt-0.5">Select a room to work in</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => router.push('/doctor/dashboard')}
              className="text-muted-foreground hover:bg-black hover:text-white"
            >
              Dashboard
            </Button>
          </div>
        </div>
      </header>

      <div className="max-w-5xl mx-auto px-6 py-10">
        {/* Title */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold tracking-tight mb-2">
            Select a Room
          </h1>
          <p className="text-muted-foreground">
            Choose the room you will work in today. The system will automatically register you into that room.
          </p>
        </div>

        {/* Search */}
        <div className="relative mb-6">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            className="pl-9"
            placeholder="Search rooms by name, type, or number..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {/* Room grid */}
        {loading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[1, 2, 3, 4, 5, 6].map((i) => (
              <Card key={i}>
                <CardContent className="p-6">
                  <Skeleton className="h-6 w-32 mb-2" />
                  <Skeleton className="h-4 w-24 mb-4" />
                  <Skeleton className="h-4 w-full" />
                </CardContent>
              </Card>
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center py-16 text-muted-foreground">
            <DoorOpen className="w-12 h-12 mb-4 opacity-30" />
            <p className="font-medium">No rooms found</p>
            {search && (
              <p className="text-sm mt-1">
                Try searching for a different keyword
              </p>
            )}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filtered.map((room) => {
              const activeDoctors = room.roomAssignments?.filter((a) => a.isActive) ?? []
              const isCheckingIn = checkingIn === room.id

              return (
                <Card
                  key={room.id}
                  className="cursor-pointer transition-all hover:shadow-md hover:-translate-y-0.5 active:translate-y-0"
                  onClick={() => !isCheckingIn && handleSelectRoom(room)}
                >
                  <CardHeader className="pb-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <CardTitle className="text-base truncate">
                          {room.name}
                        </CardTitle>
                        <CardDescription className="mt-0.5">
                          {room.roomType?.name ?? 'Unassigned'}
                        </CardDescription>
                      </div>
                      {activeDoctors.length > 0 ? (
                        <Badge className="text-xs flex-shrink-0 bg-emerald-500 hover:bg-emerald-500">
                          {activeDoctors.length} doctors
                        </Badge>
                      ) : (
                        <Badge variant="secondary" className="text-xs flex-shrink-0">
                          Empty
                        </Badge>
                      )}
                    </div>
                  </CardHeader>

                  <CardContent>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3 text-xs text-muted-foreground">
                        <div className="flex items-center gap-1">
                          <Hash className="w-3 h-3" />
                          <span>P.{room.roomNumber}</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Users className="w-3 h-3" />
                          <span>{room.capacity}</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          <span>~{formatMinutesFromSeconds(room.avgProcessTime)}</span>
                        </div>
                      </div>

                      {isCheckingIn && (
                        <Loader2 className="w-4 h-4 animate-spin text-primary" />
                      )}
                    </div>
                  </CardContent>
                </Card>
              )
            })}
          </div>
        )}
      </div>

      <AlertDialog open={showActiveRoomDialog} onOpenChange={setShowActiveRoomDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>You are currently in a clinic room</AlertDialogTitle>
            <AlertDialogDescription>
              You have not checked out of the current room.
              {currentAssignment?.room?.name
                ? ` Current room: ${currentAssignment.room.name} (P.${currentAssignment.room.roomNumber}).`
                : ''}
              {' '}You can go back to the current room or check out before selecting a different room.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel
              onClick={handleGoBackToCurrentRoom}
              disabled={!currentAssignment}
            >
              Go Back to Current Room
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleCheckOutCurrentRoom}
              disabled={checkingOutCurrent || !currentAssignment}
            >
              {checkingOutCurrent ? 'Checking out...' : 'Checkout to select a different room'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}