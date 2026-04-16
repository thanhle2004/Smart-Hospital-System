// features/doctor/room/components/CurrentPatient.tsx
'use client'

import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import {
  CheckCircle2,
  ChevronRight,
  User,
  Stethoscope,
  Calendar,
  Timer,
  GitBranch,
} from 'lucide-react'
import { VisitFlowPanel } from './VisitFlowPanel'
import type { VisitRoom } from '../types/room.type'

function formatDuration(startTime: string): string {
  const diffMs = Date.now() - new Date(startTime).getTime()
  const diffMin = Math.floor(diffMs / 60_000)
  if (diffMin < 1) return '< 1 minute'
  if (diffMin < 60) return `${diffMin} minutes`
  const h = Math.floor(diffMin / 60)
  const m = diffMin % 60
  return `${h} hours ${m > 0 ? m + ' minutes' : ''}`.trim()
}

interface CurrentPatientProps {
  inProgress: VisitRoom[]
  loading: boolean
  waitingCount: number
  canCallNext: boolean
  actionLoading: boolean
  onComplete: (visitRoomId: number) => void
  onCallNext: () => void
}

export function CurrentPatient({
  inProgress,
  loading,
  waitingCount,
  canCallNext,
  actionLoading,
  onComplete,
  onCallNext,
}: CurrentPatientProps) {
  const [flowVisitId, setFlowVisitId] = useState<string | null>(null)

  if (loading) {
    return (
      <Card>
        <CardContent className="p-6">
          <Skeleton className="h-40 w-full rounded-lg" />
        </CardContent>
      </Card>
    )
  }

  // No patient in progress
  if (inProgress.length === 0) {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center py-14 gap-4">
          <div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center">
            <User className="w-7 h-7 text-muted-foreground opacity-40" />
          </div>
          <div className="text-center">
            <p className="font-medium">No patient currently being examined</p>
            <p className="text-sm text-muted-foreground mt-1">
              {waitingCount > 0
                ? `There are ${waitingCount} patients waiting`
                : 'The waiting list is empty'}
            </p>
          </div>
          {canCallNext && (
            <Button
              onClick={onCallNext}
              disabled={actionLoading}
              size="lg"
              className="mt-2"
            >
              Call Next Patient
              <ChevronRight className="w-4 h-4 ml-1" />
            </Button>
          )}
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      {inProgress.map((visitRoom, index) => {
        const patient = visitRoom.visit.patient
        const age = new Date().getFullYear() - patient.yearOfBirth
        const isFlowOpen = flowVisitId === visitRoom.visitId

        return (
          <Card key={visitRoom.id} className="border-primary/20 bg-primary/[0.03]">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm flex items-center gap-2">
                  <span className="relative flex h-2.5 w-2.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
                  </span>
                  Currently Examining #{index + 1}
                </CardTitle>
                <Badge variant="outline" className="text-xs">
                  {patient.patientType.name}
                </Badge>
              </div>
            </CardHeader>

            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
                    Full Name
                  </p>
                  <div className="flex items-center gap-1.5">
                    <User className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
                    <span className="font-semibold text-sm">{patient.name}</span>
                  </div>
                </div>

                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
                    Year of Birth
                  </p>
                  <div className="flex items-center gap-1.5">
                    <Calendar className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
                    <span className="font-semibold text-sm">
                      {patient.yearOfBirth}{' '}
                      <span className="text-muted-foreground font-normal">
                        ({age} years old)
                      </span>
                    </span>
                  </div>
                </div>

                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
                    Service
                  </p>
                  <div className="flex items-center gap-1.5">
                    <Stethoscope className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
                    <span className="font-medium text-sm">
                      {visitRoom.visit.flow?.name ?? 'Unknown service'}
                    </span>
                  </div>
                </div>

                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
                    Examination Time
                  </p>
                  <div className="flex items-center gap-1.5">
                    <Timer className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
                    <span className="font-medium text-sm">
                      {visitRoom.startTime
                        ? formatDuration(visitRoom.startTime)
                        : 'Not started'}
                    </span>
                  </div>
                </div>
              </div>

              <Separator />

              <div className="flex gap-2">
                {canCallNext && index === 0 && (
                  <Button
                    variant="secondary"
                    size="sm"
                    className="flex-1"
                    onClick={onCallNext}
                    disabled={actionLoading}
                  >
                    <ChevronRight className="w-3.5 h-3.5 mr-1.5" />
                    Call Next Patient
                  </Button>
                )}
                <Button
                  variant="outline"
                  size="sm"
                  className="flex-1"
                  onClick={() => setFlowVisitId((prev) => (prev === visitRoom.visitId ? null : visitRoom.visitId))}
                >
                  <GitBranch className="w-3.5 h-3.5 mr-1.5" />
                  {isFlowOpen ? 'Hide' : 'View'} Visit Flow
                  <ChevronRight
                    className={`w-3.5 h-3.5 ml-1.5 transition-transform duration-200 ${
                      isFlowOpen ? 'rotate-90' : ''
                    }`}
                  />
                </Button>
                <Button
                  size="sm"
                  className="flex-1 bg-emerald-600 hover:bg-emerald-700"
                  onClick={() => onComplete(visitRoom.id)}
                  disabled={actionLoading}
                >
                  <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />
                  Complete Examination
                </Button>
              </div>

              {isFlowOpen && <VisitFlowPanel visitId={visitRoom.visitId} />}
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}