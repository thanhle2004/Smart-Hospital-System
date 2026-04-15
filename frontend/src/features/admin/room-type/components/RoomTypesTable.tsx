"use client";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { MoreHorizontal, Pencil, Trash2 } from "lucide-react";
import { RoomType } from "../types/room-type.type";
import { formatMinutesFromSeconds } from '@/lib/time';

interface RoomTypesTableProps {
  roomTypes: RoomType[];
  onEdit: (rt: RoomType) => void;
  onDelete: (rt: RoomType) => void;
}

export function RoomTypesTable({ roomTypes, onEdit, onDelete }: RoomTypesTableProps) {
  if (roomTypes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <p className="text-muted-foreground text-sm">No room types found.</p>
        <p className="text-muted-foreground text-xs mt-1">
          Click &quot;Add Room Type&quot; to create one.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[40px]">#</TableHead>
            <TableHead>Name</TableHead>
            <TableHead>Description</TableHead>
            <TableHead>Avg Process Time (minutes)</TableHead>
            <TableHead>Default Capacity</TableHead>
            <TableHead>Rooms</TableHead>
            <TableHead className="w-[60px]" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {roomTypes.map((rt, index) => (
            <TableRow key={rt.id}>
              <TableCell className="text-muted-foreground text-xs">
                {index + 1}
              </TableCell>

              <TableCell className="font-medium">{rt.name}</TableCell>

              <TableCell className="text-muted-foreground text-sm max-w-[260px] truncate">
                {rt.description ?? (
                  <span className="italic">No description</span>
                )}
              </TableCell>

              <TableCell className="tabular-nums">
                {formatMinutesFromSeconds(rt.avgProcessTime)}
              </TableCell>

              <TableCell className="tabular-nums">
                {rt.defaultCapacity}
              </TableCell>

              <TableCell className="tabular-nums text-muted-foreground">
                {rt._count?.rooms ?? 0}
              </TableCell>

              <TableCell>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="icon" className="h-8 w-8">
                      <MoreHorizontal className="h-4 w-4" />
                      <span className="sr-only">Open menu</span>
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={() => onEdit(rt)}>
                      <Pencil className="mr-2 h-4 w-4" />
                      Edit
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      onClick={() => onDelete(rt)}
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