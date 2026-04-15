// features/doctor/dashboard/components/StatsCards.tsx
'use client'

import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Users, Clock, Stethoscope, CheckCircle2 } from 'lucide-react'
import type { DoctorStats } from '../types/dashboard.type'

interface StatsCardsProps {
  stats: DoctorStats | null
  loading: boolean
}

const STAT_CONFIG = [
  {
    key: 'totalToday' as const,
    label: 'Sum of patients today',
    icon: Users,
    colorClass: 'text-blue-600',
    bgClass: 'bg-blue-50',
  },
  {
    key: 'waiting' as const,
    label: 'Waiting patients',
    icon: Clock,
    colorClass: 'text-amber-600',
    bgClass: 'bg-amber-50',
  },
  {
    key: 'inProgress' as const,
    label: 'In Progress',
    icon: Stethoscope,
    colorClass: 'text-violet-600',
    bgClass: 'bg-violet-50',
  },
  {
    key: 'completed' as const,
    label: 'Completed',
    icon: CheckCircle2,
    colorClass: 'text-emerald-600',
    bgClass: 'bg-emerald-50',
  },
]

export function StatsCards({ stats, loading }: StatsCardsProps) {
  if (loading) {
    return (
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <Card key={i}>
            <CardContent className="p-6">
              <Skeleton className="h-4 w-24 mb-4" />
              <Skeleton className="h-8 w-12" />
            </CardContent>
          </Card>
        ))}
      </div>
    )
  }

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {STAT_CONFIG.map(({ key, label, icon: Icon, colorClass, bgClass }) => (
        <Card key={key} className="hover:shadow-md transition-shadow">
          <CardContent className="p-6">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm text-muted-foreground font-medium">
                {label}
              </span>
              <div className={`p-2 rounded-lg ${bgClass}`}>
                <Icon className={`w-4 h-4 ${colorClass}`} />
              </div>
            </div>
            <p className="text-3xl font-bold tracking-tight">
              {stats?.[key] ?? 0}
            </p>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}