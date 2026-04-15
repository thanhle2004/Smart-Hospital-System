'use client';

import {
  Table,
  TableHeader,
  TableRow,
  TableHead,
  TableBody,
  TableCell,
} from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { MoreHorizontal, Pencil, Trash2, Network } from 'lucide-react';
import type { Flow } from '../types/flow.type';

interface Props {
  flows: Flow[];
  isLoading: boolean;
  onEdit: (flow: Flow) => void;
  onDelete: (flow: Flow) => void;
}

function LoadingRows() {
  return (
    <>
      {Array.from({ length: 5 }).map((_, i) => (
        <TableRow key={i}>
          <TableCell><Skeleton className="h-4 w-8" /></TableCell>
          <TableCell><Skeleton className="h-4 w-48" /></TableCell>
          <TableCell><Skeleton className="h-4 w-24" /></TableCell>
          <TableCell><Skeleton className="h-4 w-16" /></TableCell>
          <TableCell className="text-right"><Skeleton className="h-8 w-20 ml-auto" /></TableCell>
        </TableRow>
      ))}
    </>
  );
}

export function FlowsTable({ flows, isLoading, onEdit, onDelete }: Props) {
  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-16">#</TableHead>
            <TableHead>Flow</TableHead>
            <TableHead>Rooms</TableHead>
            <TableHead className="w-28 text-center">Dependencies</TableHead>
            <TableHead className="text-right w-32">Actions</TableHead>
          </TableRow>
        </TableHeader>

        <TableBody>
          {isLoading ? (
            <LoadingRows />
          ) : flows.length === 0 ? (
            <TableRow>
              <TableCell
                colSpan={5}
                className="text-center py-16 text-muted-foreground"
              >
                <div className="flex flex-col items-center gap-2">
                  <Network className="w-8 h-8 opacity-30" />
                  <span>No flows available. Create your first flow!</span>
                </div>
              </TableCell>
            </TableRow>
          ) : (
            flows.map((flow, index) => (
              <TableRow key={flow.id}>
                {/* Row number */}
                <TableCell className="text-muted-foreground font-mono text-sm">
                  {index + 1}
                </TableCell>

                {/* Name */}
                <TableCell className="font-medium">{flow.name}</TableCell>

                {/* Rooms */}
                <TableCell>
                  <div className="flex flex-wrap gap-1.5">
                    {flow.flowRooms.length === 0 ? (
                      <span className="text-muted-foreground text-sm italic">
                        No rooms added
                      </span>
                    ) : (
                      flow.flowRooms
                        .slice()
                        .sort((a, b) => a.defaultOrder - b.defaultOrder)
                        .map((fr) => (
                          <Badge
                            key={fr.id}
                            variant="secondary"
                            className="text-xs gap-1"
                          >
                            <span className="text-muted-foreground">
                              {fr.defaultOrder}.
                            </span>
                            {fr.roomType?.name ?? `Room ${fr.roomTypeId}`}
                          </Badge>
                        ))
                    )}
                  </div>
                </TableCell>

                {/* Dep count */}
                <TableCell className="text-center">
                  {(flow.dependencies?.length ?? 0) > 0 ? (
                    <Badge variant="outline">
                      {flow.dependencies.length}
                    </Badge>
                  ) : (
                    <span className="text-muted-foreground text-sm">—</span>
                  )}
                </TableCell>

                {/* Actions */}
                <TableCell className="text-right">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon" className="h-8 w-8">
                        <MoreHorizontal className="w-4 h-4" />
                        <span className="sr-only">Open action menu</span>
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem onClick={() => onEdit(flow)}>
                        <Pencil className="mr-2 h-4 w-4" />
                        Edit
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        onClick={() => onDelete(flow)}
                        className="text-destructive focus:text-destructive"
                      >
                        <Trash2 className="mr-2 h-4 w-4" />
                        Delete
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}