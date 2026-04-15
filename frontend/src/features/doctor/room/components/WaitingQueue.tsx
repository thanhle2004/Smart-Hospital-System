// features/doctor/room/components/WaitingQueue.tsx
'use client'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { Users, SkipForward, Clock } from 'lucide-react'
import type { VisitRoom } from '../types/room.type'

const PATIENT_TYPE_COLOR: Record<string, string> = {
  EMERGENCY: 'bg-red-500',
  PRIORITY: 'bg-amber-500',
  REGULAR: 'bg-sky-400',
}

function getTypeColor(code: string): string {
  return PATIENT_TYPE_COLOR[code] ?? 'bg-slate-400'
}

function formatWaitTime(createdAt: string): string {
  const diffMs = Date.now() - new Date(createdAt).getTime()
  const diffMin = Math.floor(diffMs / 60_000)
  if (diffMin < 1) return '< 1 minute'
  if (diffMin < 60) return `${diffMin} minutes`
  const h = Math.floor(diffMin / 60)
  const m = diffMin % 60
  return `${h}h${m > 0 ? m + 'm' : ''}`
}

interface WaitingQueueProps {
  waiting: VisitRoom[]
  loading: boolean
  actionLoading: boolean
  onSkip: (visitRoomId: number) => void
}

export function WaitingQueue({
  waiting,
  loading,
  actionLoading,
  onSkip,
}: WaitingQueueProps) {
  return (
    <Card className="flex-1">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <Users className="w-4 h-4 text-primary" />
          Patients in Waiting
          <Badge variant="secondary">{waiting.length}</Badge>
        </CardTitle>
      </CardHeader>

      <CardContent className="p-0">
        {loading ? (
          <div className="px-4 pb-4 space-y-2">
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-16 w-full rounded-lg" />
            ))}
          </div>
        ) : waiting.length === 0 ? (
          <div className="flex flex-col items-center py-10 text-muted-foreground">
            <Users className="w-8 h-8 mb-2 opacity-30" />
            <p className="text-sm">No patients in waiting</p>
          </div>
        ) : (
          <div className="divide-y">
            {waiting.map((vr, index) => {
              const patient = vr.visit.patient
              const age = new Date().getFullYear() - patient.yearOfBirth
              const typeCode = patient.patientType.code

              return (
                <div
                  key={vr.id}
                  className="flex items-center gap-3 px-4 py-3 hover:bg-muted/40 transition-colors"
                >
                  {/* Number */}
                  <span className="w-6 text-center text-base font-bold text-muted-foreground flex-shrink-0">
                    {index + 1}
                  </span>

                  {/* Type indicator */}
                  <div
                    className={`w-1 h-10 rounded-full flex-shrink-0 ${getTypeColor(typeCode)}`}
                  />

                  {/* Patient info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium text-sm truncate">
                        {patient.name}
                      </span>
                      <Badge variant="outline" className="text-xs py-0 h-4">
                        {patient.patientType.name}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-2 mt-0.5 text-xs text-muted-foreground">
                      <span>Born {patient.yearOfBirth}</span>
                      <span>•</span>
                      <span>{age} years old</span>
                      <span>•</span>
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        <span>{formatWaitTime(vr.createdAt)}</span>
                      </div>
                    </div>
                  </div>

                  {/* Skip */}
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 flex-shrink-0 text-muted-foreground hover:text-destructive"
                          disabled={actionLoading}
                          onClick={() => onSkip(vr.id)}
                        >
                          <SkipForward className="w-3.5 h-3.5" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent side="left">Skip</TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                </div>
              )
            })}
          </div>
        )}
      </CardContent>
    </Card>
  )
}