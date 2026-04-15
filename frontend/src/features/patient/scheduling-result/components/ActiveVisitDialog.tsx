'use client'

import { useRouter } from 'next/navigation'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { AlertCircle } from 'lucide-react'

interface ActiveVisitDialogProps {
  open: boolean
  visitId: string | null
  onOpenChange: (open: boolean) => void
}

export default function ActiveVisitDialog({
  open,
  visitId,
  onOpenChange,
}: ActiveVisitDialogProps) {
  const router = useRouter()

  const handleNavigate = () => {
    if (visitId) {
      router.push(
        `/patient/scheduling-result?visitId=${visitId}`,
      )
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <div className="flex items-center gap-3">
            <AlertCircle className="h-6 w-6 text-orange-600" />
            <AlertDialogTitle>Your visit is in progress</AlertDialogTitle>
          </div>
          <AlertDialogDescription className="mt-4">
            You have an ongoing appointment. Please navigate to the appointment page to continue monitoring.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogAction onClick={handleNavigate}>
            Go to appointment page
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
