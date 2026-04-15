import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

// --- User Status Badge ---

interface UserStatusBadgeProps {
  isActive: boolean;
}

export function UserStatusBadge({ isActive }: UserStatusBadgeProps) {
  // Map style by status
  const statusConfig = isActive 
    ? { label: 'Active', className: 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400' }
    : { label: 'Inactive', className: 'bg-zinc-50 text-zinc-600 border-zinc-200 dark:bg-zinc-500/10 dark:text-zinc-400' };

  return (
    <Badge 
      variant="outline" 
      className={cn("font-medium", statusConfig.className)}
    >
      {statusConfig.label}
    </Badge>
  );
}

// --- User Role Badge ---

interface UserRoleBadgeProps {
  role: 'ADMIN' | 'DOCTOR';
}

export function UserRoleBadge({ role }: UserRoleBadgeProps) {
  // Object mapping is easier to extend (e.g. add 'NURSE', 'STAFF')
  const roleMap: Record<UserRoleBadgeProps['role'], { label: string; className: string }> = {
    ADMIN: { 
      label: 'Admin', 
      className: 'border-red-200 bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-400' 
    },
    DOCTOR: { 
      label: 'Doctor', 
      className: 'border-blue-200 bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400' 
    },
  };

  const { label, className } = roleMap[role];

  return (
    <Badge 
      variant="outline" 
      className={cn("capitalize shadow-sm", className)}
    >
      {label}
    </Badge>
  );
}