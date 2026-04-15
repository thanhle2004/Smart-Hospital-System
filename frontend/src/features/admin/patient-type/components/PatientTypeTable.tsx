'use client';

import { useState } from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { MoreHorizontal, Pencil, Trash2 } from 'lucide-react';
import { PatientType } from '../types/patient-type.type';
import { Skeleton } from '@/components/ui/skeleton';

interface PatientTypeTableProps {
  data: PatientType[];
  isLoading: boolean;
  onEdit: (item: PatientType) => void;
  onDelete: (item: PatientType) => void;
  onToggleActive: (id: number) => Promise<void>;
}

export function PatientTypeTable({
  data,
  isLoading,
  onEdit,
  onDelete,
  onToggleActive,
}: PatientTypeTableProps) {
  const [togglingId, setTogglingId] = useState<number | null>(null);

  const handleToggle = async (id: number) => {
    setTogglingId(id);
    await onToggleActive(id);
    setTogglingId(null);
  };

  if (isLoading) {
    return (
      <div className="space-y-3 p-4">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full rounded-md" />
        ))}
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center text-muted-foreground">
        <p className="text-sm">No patient types found.</p>
        <p className="text-xs mt-1">Press &quot;Add new&quot; to get started.</p>
      </div>
    );
  }

  return (
    <div className="rounded-md border overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow className="bg-muted/50">
            <TableHead className="w-12 text-center">#</TableHead>
            <TableHead className="w-32">Code</TableHead>
            <TableHead>Name</TableHead>
            <TableHead>Description</TableHead>
            <TableHead className="w-28 text-center">Priority</TableHead>
            <TableHead className="w-28 text-center">Status</TableHead>
            <TableHead className="w-16 text-center">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.map((item, index) => (
            <TableRow key={item.id} className="hover:bg-muted/30 transition-colors">
              <TableCell className="text-center text-muted-foreground text-sm">
                {index + 1}
              </TableCell>
              <TableCell>
                <Badge variant="outline" className="font-mono text-xs">
                  {item.code}
                </Badge>
              </TableCell>
              <TableCell className="font-medium">{item.name}</TableCell>
              <TableCell className="text-sm text-muted-foreground max-w-xs truncate">
                {item.description ?? (
                  <span className="italic text-muted-foreground/50">—</span>
                )}
              </TableCell>
              <TableCell className="text-center">
                {item.basePriority != null ? (
                  <span className="text-sm font-semibold">{item.basePriority}</span>
                ) : (
                  <span className="text-muted-foreground/50 text-sm italic">—</span>
                )}
              </TableCell>
              <TableCell className="text-center">
                <Switch
                  checked={item.isActive}
                  disabled={togglingId === item.id}
                  onCheckedChange={() => handleToggle(item.id)}
                  aria-label={`Toggle active for ${item.name}`}
                />
              </TableCell>
              <TableCell className="text-center">
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      aria-label="Open action menu"
                    >
                      <MoreHorizontal className="h-4 w-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={() => onEdit(item)}>
                      <Pencil className="mr-2 h-4 w-4" />
                      Edit
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      onClick={() => onDelete(item)}
                      className="text-destructive focus:text-destructive"
                    >
                      <Trash2 className="mr-2 h-4 w-4" />
                      Delete
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}