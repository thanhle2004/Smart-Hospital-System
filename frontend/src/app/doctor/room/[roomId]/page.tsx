// app/doctor/room/[roomId]/page.tsx
'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { authService } from '@/features/auth/services/auth.service'
import { doctorRoomService } from '@/features/doctor/room/services/room.service'
import { useRoomDetail } from '@/features/doctor/room/hooks/useRoomDetail'
import { useRoomQueue } from '@/features/doctor/room/hooks/useRoomQueue'
import { RoomHeader } from '@/features/doctor/room/components/RoomHeader'
import { DoctorList } from '@/features/doctor/room/components/DoctorList'
import { WaitingQueue } from '@/features/doctor/room/components/WaitingQueue'
import { CurrentPatient } from '@/features/doctor/room/components/CurrentPatient'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
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
  ArrowLeft,
  Monitor,
  LogOut,
  RefreshCw,
  Stethoscope,
} from 'lucide-react'
import { toast } from 'sonner'
import type { MeResponse } from '@/features/auth/types/auth.type'

export default function DoctorRoomPage() {
  const params = useParams()
  const roomId = Number(params.roomId)
  const router = useRouter()

  const [user, setUser] = useState<MeResponse | null>(null)
  const [showCheckOutDialog, setShowCheckOutDialog] = useState(false)
  const [checkingOut, setCheckingOut] = useState(false)

  const { room, loading: roomLoading, refetch: refetchRoom } = useRoomDetail(roomId)
  const {
    waiting,
    inProgress,
    current,
    inProgressCount,
    loading: queueLoading,
    actionLoading,
    callNext,
    completeCurrent,
    skipPatient,
  } = useRoomQueue(roomId)

  useEffect(() => {
    authService
      .me()
      .then(setUser)
      .catch(() => router.push('/login'))
  }, [router])

  const handleCallNext = async () => {
    try {
      await callNext()
      toast.success('Called next patient')
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'There was an error calling next patient')
    }
  }

  const handleComplete = async (visitRoomId: number) => {
    try {
      await completeCurrent(visitRoomId)
      toast.success('Complete patient')
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'There was an error completing the patient')
    }
  }

  const handleSkip = async (visitRoomId: number) => {
    try {
      await skipPatient(visitRoomId)
      toast.info('Skipped patient')
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'There was an error skipping the patient')
    }
  }

  const handleCheckOut = async () => {
    setCheckingOut(true)
    try {
      await doctorRoomService.checkOut(roomId)
      toast.success('Checked out of room')
      router.push('/doctor/room/select')
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Cannot leave room at this time')
    } finally {
      setCheckingOut(false)
      setShowCheckOutDialog(false)
    }
  }

  // Loading state
  if (roomLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50">
        <div className="flex items-center gap-3 text-muted-foreground">
          <RefreshCw className="w-5 h-5 animate-spin" />
          <span>Loading room...</span>
        </div>
      </div>
    )
  }

  // Not found
  if (!room) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50">
        <div className="text-center">
          <p className="font-medium text-lg mb-4">Room not found</p>
          <Button
            variant="outline"
            onClick={() => router.push('/doctor/room/select')}
          >
            Go back to room selection
          </Button>
        </div>
      </div>
    )
  }

  const canCallNext = waiting.length > 0 && inProgressCount < room.capacity

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      {/* Top navigation */}
      <header className="bg-white border-b sticky top-0 z-20 flex-shrink-0">
        <div className="max-w-screen-xl mx-auto px-6 h-14 flex items-center gap-3">
          {/* Back */}
          <Button
            variant="outline"
            size="icon"
            title="Dashboard"
            className="h-8 w-28 flex-shrink-0 hover:bg-black hover:text-white"
            onClick={() => router.push('/doctor/dashboard')}
          >
            
            <ArrowLeft className="w-4 h-4" /> Dashboard
          </Button>

          {/* Room name */}
          <div className="flex items-center gap-2">
            <Stethoscope className="w-4 h-4 text-primary flex-shrink-0" />
            <span className="font-semibold text-sm">{room.name}</span>
          </div>

          <Separator orientation="vertical" className="h-5 mx-1" />

          {/* Doctor name */}
          <span className="text-sm text-muted-foreground flex-1 truncate">
            {user?.profile?.fullName ?? user?.email}
          </span>

          {/* Hallway display */}
          <Button
            variant="outline"
            size="sm"
            className="flex-shrink-0 hover:bg-black hover:text-white"
            onClick={() =>
              window.open(`/doctor/room/${roomId}/display`, '_blank')
            }
          >
            <Monitor className="w-3.5 h-3.5 mr-1.5" />
            Hallway Display
          </Button>

          {/* Check out */}
          <Button
            variant="outline"
            size="sm"
            className="text-destructive flex-shrink-0 hover:bg-black hover:text-white"
            onClick={() => setShowCheckOutDialog(true)}
          >
            <LogOut className="w-3.5 h-3.5 mr-1.5" />
            Leave Room
          </Button>
        </div>
      </header>

      {/* Main content */}
      <div className="flex-1 max-w-screen-xl mx-auto w-full px-6 py-6 space-y-6">
        {/* Room header */}
        <div className="bg-white rounded-xl border p-6">
          <RoomHeader room={room} />
        </div>

        {/* Call-next banner - shown when no patient is in progress */}
        {!queueLoading && canCallNext && (
          <div className="bg-amber-50 border border-amber-200 rounded-xl px-5 py-4 flex items-center justify-between gap-4">
            <div>
              <p className="font-semibold text-amber-900">
                There are {waiting.length} patients waiting
              </p>
              <p className="text-sm text-amber-700 mt-0.5">
                {room.capacity > 1
                  ? `Current in examination: ${inProgressCount}/${room.capacity}. You can call more patients.`
                  : 'Click the button to call the next patient for examination'}
              </p>
            </div>
            <Button
              onClick={handleCallNext}
              disabled={actionLoading}
              className="bg-amber-600 hover:bg-amber-700 flex-shrink-0"
            >
              Call Patient
            </Button>
          </div>
        )}

        {/* Two-column layout */}
        <div className="grid grid-cols-12 gap-6 items-start">
          {/* LEFT col: Doctors + Queue */}
          <div className="col-span-12 lg:col-span-5 space-y-4">
            <DoctorList
              roomId={roomId}
              currentUserId={user?.id ?? ''}
              onCapacityChange={refetchRoom}
            />
            <WaitingQueue
              waiting={waiting}
              loading={queueLoading}
              actionLoading={actionLoading}
              onSkip={handleSkip}
            />
          </div>

          {/* RIGHT col: Current patient + flow */}
          <div className="col-span-12 lg:col-span-7 space-y-4">
            <CurrentPatient
              inProgress={inProgress}
              loading={queueLoading}
              waitingCount={waiting.length}
              canCallNext={canCallNext}
              actionLoading={actionLoading}
              onComplete={handleComplete}
              onCallNext={handleCallNext}
            />
          </div>
        </div>
      </div>

      {/* Check-out confirmation dialog */}
      <AlertDialog open={showCheckOutDialog} onOpenChange={setShowCheckOutDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Leave Room?</AlertDialogTitle>
            <AlertDialogDescription>
              You will be logged out of{' '}
              <span className="font-medium text-foreground">{room.name}</span>.
              The room's capacity will decrease. Are you sure?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={checkingOut}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleCheckOut}
              disabled={checkingOut}
              className="bg-destructive hover:bg-destructive/90"
            >
              {checkingOut ? 'Processing...' : 'Leave Room'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}