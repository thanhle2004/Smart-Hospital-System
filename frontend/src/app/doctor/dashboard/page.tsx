// app/doctor/dashboard/page.tsx
'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { authService } from '@/features/auth/services/auth.service'
import { CurrentAssignment, doctorRoomService } from '@/features/doctor/room/services/room.service'
import { useDashboard } from '@/features/doctor/dashboard/hooks/useDashboard'
import { StatsCards } from '@/features/doctor/dashboard/components/StatsCards'
import { ActiveRoomsList } from '@/features/doctor/dashboard/components/ActiveRoomsList'
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
  DoorOpen,
  LogOut,
  RefreshCw,
  Stethoscope,
  LayoutDashboard,
} from 'lucide-react'
import { toast } from 'sonner'
import type { MeResponse } from '@/features/auth/types/auth.type'

export default function DoctorDashboardPage() {
  const router = useRouter()
  const [user, setUser] = useState<MeResponse | null>(null)
  const [currentAssignment, setCurrentAssignment] = useState<CurrentAssignment | null>(null)
  const [showLogoutGuardDialog, setShowLogoutGuardDialog] = useState(false)
  const [checkingOutAndLogout, setCheckingOutAndLogout] = useState(false)
  const { stats, activeRooms, loading, refetch } = useDashboard()

  useEffect(() => {
    authService.me()
      .then(setUser)
      .catch(() => router.push('/login'))
  }, [router])

  useEffect(() => {
    doctorRoomService
      .getCurrentAssignment()
      .then(setCurrentAssignment)
      .catch(() => setCurrentAssignment(null))
  }, [])

  const handleLogout = async () => {
    if (currentAssignment) {
      setShowLogoutGuardDialog(true)
      return
    }

    try {
      await authService.logout()
      router.push('/login')
    } catch {
      toast.error('Unable to logout. Please try again.')
    }
  }

  const handleBackToCurrentRoom = () => {
    if (!currentAssignment) return
    router.push(`/doctor/room/${currentAssignment.roomId}`)
  }

  const handleCheckoutAndLogout = async () => {
    if (!currentAssignment) return

    setCheckingOutAndLogout(true)
    try {
      await doctorRoomService.checkOut(currentAssignment.roomId)
      await authService.logout()
      router.push('/login')
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Unable to checkout and logout')
    } finally {
      setCheckingOutAndLogout(false)
    }
  }

  const today = new Date().toLocaleDateString('en-US', {
    weekday: 'long',
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  })

  return (
    <div className="min-h-screen bg-slate-50 flex">
      {/* Sidebar */}
      <aside className="w-56 bg-white border-r flex flex-col flex-shrink-0 sticky top-0 h-screen">
        {/* Logo */}
        <div className="p-5 border-b">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
              <Stethoscope className="w-4 h-4 text-primary-foreground" />
            </div>
            <span className="font-bold text-sm">Clinic System</span>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 p-3 space-y-1">
          <div className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-black text-white font-medium text-sm">
            <LayoutDashboard className="w-4 h-4" />
            Dashboard
          </div>
          <button
            onClick={() => router.push('/doctor/room/select')}
            className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-muted-foreground hover:bg-muted hover:text-foreground hover:shadow-sm active:scale-[0.98] transition-all duration-150 text-sm"
          >
            <DoorOpen className="w-4 h-4" />
            Enter Room
          </button>
        </nav>

        {/* User info */}
        <div className="p-3 border-t">
          <div className="flex items-center gap-2.5 mb-2 px-2">
            <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
              <span className="text-xs font-bold text-primary">
                {(user?.profile?.fullName ?? user?.email ?? 'U')
                  .split(' ')
                  .pop()
                  ?.[0]?.toUpperCase()}
              </span>
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium truncate">
                {user?.profile?.fullName ?? user?.email}
              </p>
              <p className="text-[11px] text-muted-foreground">Doctor</p>
            </div>
          </div>
          <Button
            variant="ghost"
            size="sm"
            className="w-full justify-start text-muted-foreground text-xs h-8"
            onClick={handleLogout}
          >
            <LogOut className="w-3.5 h-3.5 mr-2" />
            Logout
          </Button>
        </div>
      </aside>

      {/* Main */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="bg-white border-b px-8 py-4 flex items-center justify-between flex-shrink-0 sticky top-0 z-10">
          <div>
            <h1 className="text-xl font-bold">Dashboard</h1>
            <p className="text-xs text-muted-foreground capitalize mt-0.5">{today}</p>
          </div>
          <div className="flex items-center gap-3">
            <Button
              variant="outline"
              size="sm"
              onClick={refetch}
              disabled={loading}
            >
              <RefreshCw
                className={`w-3.5 h-3.5 mr-1.5 ${loading ? 'animate-spin' : ''}`}
              />
              Refresh
            </Button>
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 p-8 space-y-8 overflow-auto">
          <section>
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-4">
              Today’s Overview
            </h2>
            <StatsCards stats={stats} loading={loading} />
          </section>

          <Separator />

          <section>
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-4">
              Active Rooms
            </h2>
            <ActiveRoomsList rooms={activeRooms} loading={loading} />
          </section>
        </main>
      </div>

      <AlertDialog open={showLogoutGuardDialog} onOpenChange={setShowLogoutGuardDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>You are currently in a clinic room</AlertDialogTitle>
            <AlertDialogDescription>
              You have not checked out of the current room.
              {currentAssignment?.room?.name
                ? ` Current room: ${currentAssignment.room.name} (P.${currentAssignment.room.roomNumber}).`
                : ''}
              {' '}You can go back to the current room or check out and log out.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={handleBackToCurrentRoom} disabled={!currentAssignment}>
              Go Back to Current Room
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleCheckoutAndLogout}
              disabled={checkingOutAndLogout || !currentAssignment}
            >
              {checkingOutAndLogout ? 'Processing...' : 'Checkout and Logout'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}