// features/doctor/room/components/VisitFlowPanel.tsx
'use client'

import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
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
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import {
  GitBranch,
  SkipForward,
  Undo2,
  FastForward,
  Trash2,
  Plus,
  AlertCircle,
  Lock,
  ArrowRight,
  CheckCircle2,
} from 'lucide-react'
import { useVisitFlow } from '../hooks/useVisitFlow'
import { useRoomTypes } from '../hooks/useRoomTypes'
import { toast } from 'sonner'
import type { VisitFlow } from '../types/room.type'

interface FlowStepProps {
  flow: VisitFlow
  allFlows: VisitFlow[]
  onSkip: (visitFlowId: number) => void
  onUnskip: (visitFlowId: number) => void
  onSkipOthers: (visitFlowId: number) => void
  onRemove: (visitFlowId: number) => void
  disabled: boolean
}

function FlowStep({ flow, allFlows, onSkip, onUnskip, onSkipOthers, onRemove, disabled }: FlowStepProps) {
  const requiredFlows = flow.dependencies
    .map((d) => allFlows.find((f) => f.id === d.requiredVisitFlowId))
    .filter(Boolean) as VisitFlow[]
  const requiredByFlows = flow.requiredBy
    .map((d) => allFlows.find((f) => f.id === d.visitFlowId))
    .filter(Boolean) as VisitFlow[]
  const isCompleted = Boolean(flow.isCompleted)
  const isInProgress = Boolean(flow.isInProgress)
  const isStepLocked = disabled || isCompleted || isInProgress

  return (
    <div
      className={`flex items-center gap-3 p-3 rounded-lg border transition-colors ${
        flow.isSkipped
          ? 'bg-muted/30 border-muted text-muted-foreground'
          : 'bg-background border-border'
      }`}
    >
      {/* Status icon */}
      <div className="flex-shrink-0">
        {flow.isSkipped ? (
          <SkipForward className="w-3.5 h-3.5 text-muted-foreground" />
        ) : (
          <div className="w-3.5 h-3.5 rounded-full border-2 border-primary" />
        )}
      </div>

      {/* Info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span
            className={`text-sm font-medium ${flow.isSkipped ? 'line-through' : ''}`}
          >
            {flow.roomType.name}
          </span>
          {flow.isAddedManually && (
            <Badge variant="outline" className="text-[10px] py-0 h-4">
                Added manually
            </Badge>
          )}
          {isCompleted && (
            <Badge variant="secondary" className="text-[10px] py-0 h-4">
              Completed - locked
            </Badge>
          )}
          {isInProgress && (
            <Badge variant="secondary" className="text-[10px] py-0 h-4">
              In Progress - locked
            </Badge>
          )}
          {requiredFlows.length > 0 ? (
            <Badge variant="secondary" className="text-[10px] py-0 h-4">
              {requiredFlows.length} dependency
            </Badge>
          ) : (
            <Badge variant="outline" className="text-[10px] py-0 h-4">
              No dependency
            </Badge>
          )}
          {requiredFlows.length > 0 && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger>
                  <Lock className="w-3 h-3 text-amber-500" />
                </TooltipTrigger>
                <TooltipContent>
                  Must complete before:{' '}
                  {requiredFlows.map((f) => f.roomType.name).join(', ')}
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
        </div>

        {requiredFlows.length > 0 && (
          <div className="flex items-center gap-1 mt-0.5 text-xs text-muted-foreground">
            <ArrowRight className="w-3 h-3" />
            <span>After: {requiredFlows.map((f) => f.roomType.name).join(', ')}</span>
          </div>
        )}
        {requiredByFlows.length > 0 && (
          <div className="flex items-center gap-1 mt-0.5 text-xs text-muted-foreground">
            <CheckCircle2 className="w-3 h-3" />
            <span>Required for: {requiredByFlows.map((f) => f.roomType.name).join(', ')}</span>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center gap-1 flex-shrink-0">
        {!flow.isSkipped && (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 text-muted-foreground hover:text-amber-600"
                  disabled={isStepLocked}
                  onClick={() => onSkip(flow.id)}
                >
                  <SkipForward className="w-3.5 h-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                {isCompleted
                  ? 'Step already completed'
                  : isInProgress
                    ? 'Step is currently in progress'
                    : 'Skip this step'}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        )}
        {flow.isSkipped && (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 text-muted-foreground hover:text-emerald-600"
                  disabled={isStepLocked}
                  onClick={() => onUnskip(flow.id)}
                >
                  <Undo2 className="w-3.5 h-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                {isCompleted
                  ? 'Step already completed'
                  : isInProgress
                    ? 'Step is currently in progress'
                    : 'Unskip this step'}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        )}
        {flow.isAddedManually && (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 text-muted-foreground hover:text-destructive"
                  disabled={isStepLocked}
                  onClick={() => onRemove(flow.id)}
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                {isCompleted
                  ? 'Step already completed'
                  : isInProgress
                    ? 'Step is currently in progress'
                    : 'Delete this step'}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        )}
        {!flow.isSkipped && (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 text-muted-foreground hover:text-primary"
                  disabled={isStepLocked}
                  onClick={() => onSkipOthers(flow.id)}
                >
                  <FastForward className="w-3.5 h-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                {isCompleted
                  ? 'Step already completed'
                  : isInProgress
                    ? 'Step is currently in progress'
                    : 'Skip all other skippable steps (one-time transfer)'}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        )}
      </div>
    </div>
  )
}

interface VisitFlowPanelProps {
  visitId: string
}

export function VisitFlowPanel({ visitId }: VisitFlowPanelProps) {
  const { flows, loading, addRoom, skipStep, unskipStep, skipAllExcept, removeStep } = useVisitFlow(visitId)
  const { roomTypes, loading: roomTypesLoading } = useRoomTypes()
  const [selectedRoomTypeId, setSelectedRoomTypeId] = useState<string>('')
  const [selectedDependencyIds, setSelectedDependencyIds] = useState<number[]>([])
  const [addLoading, setAddLoading] = useState(false)
  const [dependencyWarningOpen, setDependencyWarningOpen] = useState(false)
  const [dependencyWarningStepName, setDependencyWarningStepName] = useState('')

  const existingIds = new Set(flows.map((f) => f.roomTypeId))
  const availableToAdd = roomTypes.filter(
    (rt) => !existingIds.has(rt.id),
  )

  const sorted = [...flows].sort((a, b) => a.orderIndex - b.orderIndex)
  const dependencyCandidates = sorted.filter((flow) => !flow.isSkipped)

  const handleAddRoom = async () => {
    if (!selectedRoomTypeId) return
    setAddLoading(true)
    try {
      await addRoom(Number(selectedRoomTypeId), selectedDependencyIds)
      setSelectedRoomTypeId('')
      setSelectedDependencyIds([])
      toast.success('Room added to flow')
    } catch {
      toast.error('Failed to add room to flow')
    } finally {
      setAddLoading(false)
    }
  }

  const toggleDependency = (visitFlowId: number) => {
    setSelectedDependencyIds((prev) =>
      prev.includes(visitFlowId)
        ? prev.filter((id) => id !== visitFlowId)
        : [...prev, visitFlowId],
    )
  }

  const handleSkip = async (visitFlowId: number) => {
    try {
      await skipStep(visitFlowId)
      toast.info('Step skipped')
    } catch {
      toast.error('Failed to skip step')
    }
  }

  const handleUnskip = async (visitFlowId: number) => {
    try {
      await unskipStep(visitFlowId)
      toast.success('Step unskipped')
    } catch {
      toast.error('Failed to unskip step')
    }
  }

  const handleSkipOthers = async (visitFlowId: number) => {
    const selectedStep = flows.find((f) => f.id === visitFlowId)
    const hasUnmetDependencies =
      (selectedStep?.dependencies ?? []).length > 0 &&
      selectedStep!.dependencies.some((dep) => {
        const requiredStep = flows.find((f) => f.id === dep.requiredVisitFlowId)
        return !requiredStep?.isCompleted
      })

    if (selectedStep && hasUnmetDependencies) {
      setDependencyWarningStepName(selectedStep.roomType.name)
      setDependencyWarningOpen(true)
      return
    }

    try {
      await skipAllExcept(visitFlowId)
      toast.success('Other skippable steps were skipped for next transfer')
    } catch {
      toast.error('Failed to skip other steps')
    }
  }

  const handleRemove = async (visitFlowId: number) => {
    try {
      await removeStep(visitFlowId)
      toast.success('Step deleted')
    } catch {
      toast.error('Failed to delete step')
    }
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <GitBranch className="w-4 h-4 text-primary" />
          Visit Flow
          <Badge variant="secondary">{flows.length} steps</Badge>
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-3">
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-12 w-full rounded-lg" />
            ))}
          </div>
        ) : sorted.length === 0 ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground py-4 justify-center">
            <AlertCircle className="w-4 h-4" />
            No steps in the flow
          </div>
        ) : (
          <div className="space-y-1.5">
            {sorted.map((flow, idx) => (
              <div key={flow.id} className="relative">
                {idx < sorted.length - 1 && (
                  <div className="absolute left-[22px] top-full h-1.5 w-0.5 bg-border z-0" />
                )}
                <FlowStep
                  flow={flow}
                  allFlows={flows}
                  onSkip={handleSkip}
                  onUnskip={handleUnskip}
                  onSkipOthers={handleSkipOthers}
                  onRemove={handleRemove}
                  disabled={addLoading}
                />
              </div>
            ))}
          </div>
        )}

        {/* Add room */}
        {availableToAdd.length > 0 && (
          <div className="pt-2 border-t space-y-2.5">
            <div className="flex gap-2">
              <Select
                value={selectedRoomTypeId}
                onValueChange={(value) => {
                  setSelectedRoomTypeId(value)
                  setSelectedDependencyIds([])
                }}
              >
                <SelectTrigger className="flex-1 h-8 text-sm">
                  <SelectValue placeholder="Add Room..." />
                </SelectTrigger>
                <SelectContent>
                  {availableToAdd.map((rt) => (
                    <SelectItem key={rt.id} value={String(rt.id)}>
                      {rt.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                size="sm"
                className="h-8 flex-shrink-0"
                disabled={!selectedRoomTypeId || addLoading || roomTypesLoading}
                onClick={handleAddRoom}
              >
                <Plus className="w-3.5 h-3.5 mr-1" />
                  Add
              </Button>
            </div>

            {selectedRoomTypeId && dependencyCandidates.length > 0 && (
              <div className="rounded-md border bg-muted/20 p-2">
                <p className="text-xs font-medium mb-1.5">Dependencies (optional)</p>
                <p className="text-[11px] text-muted-foreground mb-2">
                  The new room will only be eligible after selected steps are completed.
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {dependencyCandidates.map((step) => {
                    const selected = selectedDependencyIds.includes(step.id)
                    return (
                      <Button
                        key={step.id}
                        type="button"
                        size="sm"
                        variant={selected ? 'default' : 'outline'}
                        className="h-7 text-xs"
                        onClick={() => toggleDependency(step.id)}
                        disabled={addLoading}
                      >
                        {step.roomType.name}
                      </Button>
                    )
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>

      <AlertDialog open={dependencyWarningOpen} onOpenChange={setDependencyWarningOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Cannot Use One-Time Transfer</AlertDialogTitle>
            <AlertDialogDescription>
              Step <span className="font-medium text-foreground">{dependencyWarningStepName}</span> still depends on other unfinished steps.
              If you skip all other steps now, the system cannot select this room.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Close</AlertDialogCancel>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}