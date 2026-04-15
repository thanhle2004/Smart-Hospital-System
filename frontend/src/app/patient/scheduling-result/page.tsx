'use client'

import { Suspense, useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import FlowRoomRow from '@/features/patient/scheduling-result/components/FlowRoomRow'
import CurrentRoomCard from '@/features/patient/scheduling-result/components/CurrentRoomCard'
import { useSchedulingResult } from '@/features/patient/scheduling-result/hooks/useSchedulingResult'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { CheckCircle } from 'lucide-react'

function SchedulingResultContent() {
  const router = useRouter()
  const [showCompletionDialog, setShowCompletionDialog] = useState(false)

  const { visit, currentRoom, error } = useSchedulingResult()

  // Prevent browser back navigation
  useEffect(() => {
    const handlePopState = (event: PopStateEvent) => {
      event.preventDefault()
      // Keep user on scheduling-result page
      window.history.pushState(null, '', window.location.href)
    }

    // Push a new history state to prevent going back
    window.history.pushState(null, '', window.location.href)

    window.addEventListener('popstate', handlePopState)
    return () => {
      window.removeEventListener('popstate', handlePopState)
    }
  }, [])

  // Check if all flows are completed
  useEffect(() => {
    if (visit && visit.visitRooms && visit.visitRooms.length > 0) {
      const allCompleted = visit.visitRooms.every(vr => vr.status === 'COMPLETED')
      setShowCompletionDialog(allCompleted && visit.visitRooms.length > 0)
    }
  }, [visit])

  if (!visit) {
    return <div className="p-10">Loading...</div>
  }

  const steps = visit.visitFlows ?? []

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-md mx-auto space-y-6">

        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {error}
          </div>
        )}

        {currentRoom && (
          <CurrentRoomCard room={currentRoom} />
        )}

        <div className="space-y-3">
          {steps.map(fr => {

            const vr = visit.visitRooms.find(
              v => (v.roomTypeId ?? v.room?.roomTypeId) === fr.roomTypeId
            )

            return (
              <FlowRoomRow
                key={fr.id}
                fr={fr}
                vr={vr}
              />
            )
          })}
        </div>

      </div>

      <AlertDialog open={showCompletionDialog} onOpenChange={setShowCompletionDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <div className="flex items-center gap-3">
              <CheckCircle className="h-6 w-6 text-green-600" />
              <AlertDialogTitle>Visit Completed</AlertDialogTitle>
            </div>
            <AlertDialogDescription className="mt-4">
              You have completed all the steps in your visit. Thank you for using our service!
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogAction 
              onClick={() => {
                setShowCompletionDialog(false)
                router.push('/patient/dashboard')
              }}
            >
              Back to Dashboard
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

export default function SchedulingResultPage() {
  return (
    <Suspense fallback={<div className="p-10">Loading...</div>}>
      <SchedulingResultContent />
    </Suspense>
  )
}