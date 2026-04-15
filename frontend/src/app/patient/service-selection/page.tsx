'use client'

import { Suspense, useState, useEffect } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { toast } from 'sonner'

import FlowList from '@/features/patient/service-selection/components/FlowList'
import { useFlows } from '@/features/patient/service-selection/hooks/useFlows'
import { checkIn } from '@/features/patient/service-selection/services/service-selection.service'
import { useActiveVisit } from '@/features/patient/scheduling-result/hooks/useActiveVisit'
import ActiveVisitDialog from '@/features/patient/scheduling-result/components/ActiveVisitDialog'

function ServiceSelectionContent() {

  const router = useRouter()
  const searchParams = useSearchParams()
  const patientId = searchParams.get('patientId')

  const { flows, loading, error } = useFlows()
  const { activeVisit, loading: visitLoading } = useActiveVisit()
  const [showActiveVisitDialog, setShowActiveVisitDialog] = useState(false)

  const [selectedFlowId, setSelectedFlowId] = useState<number | null>(null)
  const [checkInError, setCheckInError] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Show dialog if patient has active visit
  useEffect(() => {
    if (!visitLoading && activeVisit) {
      setShowActiveVisitDialog(true)
    }
  }, [activeVisit, visitLoading])

  const handleConfirm = async () => {
    if (!selectedFlowId || !patientId) return

    setIsSubmitting(true)
    setCheckInError(null)

    try {
      const data = await checkIn(patientId, selectedFlowId)
      router.push(
        `/patient/scheduling-result?visitId=${data.id}`,
      )
    } catch (e) {
      const errorMsg = e instanceof Error ? e.message : 'Failed to check in. Please try again.'
      setCheckInError(errorMsg)
      toast.error(errorMsg)
      console.error(e)
    } finally {
      setIsSubmitting(false)
    }
  }

  if (loading || visitLoading) {
    return <div className="p-10 text-center">Loading...</div>
  }

  return (
    <>
      <div className="min-h-screen bg-gray-50 px-6 py-8">
        <div className="max-w-md mx-auto space-y-6">

          <div>
            <h1 className="text-xl font-bold text-blue-900">
              Medical Services
            </h1>
            <p className="text-gray-600 text-sm">
              Select a department
            </p>
          </div>

          {(error || checkInError) && (
            <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
              {checkInError || error}
            </div>
          )}

          <FlowList
            flows={flows}
            selectedFlowId={selectedFlowId}
            onSelect={setSelectedFlowId}
          />

          <button
            onClick={handleConfirm}
            disabled={!selectedFlowId || isSubmitting}
            className="w-full h-12 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-semibold disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {isSubmitting ? 'Processing...' : 'Confirm Selection'}
          </button>

        </div>
      </div>
      <ActiveVisitDialog
        open={showActiveVisitDialog}
        visitId={activeVisit?.id || null}
        onOpenChange={setShowActiveVisitDialog}
      />
    </>
  )
}

export default function ServiceSelectionPage() {
  return (
    <Suspense fallback={<div className="p-10 text-center">Loading medical services...</div>}>
      <ServiceSelectionContent />
    </Suspense>
  )
}