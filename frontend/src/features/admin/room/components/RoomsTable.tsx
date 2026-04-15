"use client";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
import { MoreHorizontal, Pencil, Trash2 } from "lucide-react";
import { Room } from "../types/room.type";
import { formatMinutesFromSeconds } from '@/lib/time';

interface RoomsTableProps {
  rooms: Room[];
  onEdit: (room: Room) => void;
  onDelete: (room: Room) => void;
}

export function RoomsTable({ rooms, onEdit, onDelete }: RoomsTableProps) {
  if (rooms.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <p className="text-muted-foreground text-sm">No rooms found.</p>
        <p className="text-muted-foreground text-xs mt-1">
          Click &quot;Add Room&quot; to create one.
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
            <TableHead>Room No.</TableHead>
            <TableHead>Room Type</TableHead>
            <TableHead>Capacity</TableHead>
            <TableHead>Avg Process Time (minutes)</TableHead>
            <TableHead>Action</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rooms.map((room, index) => (
            <TableRow key={room.id}>
              <TableCell className="text-muted-foreground text-xs">
                {index + 1}
              </TableCell>

              <TableCell className="font-medium">{room.name}</TableCell>

              <TableCell>
                <span className="tabular-nums font-semibold">
                  {room.roomNumber}
                </span>
              </TableCell>

              <TableCell>
                <Badge variant="outline">{room.roomType?.name ?? "Unassigned"}</Badge>
              </TableCell>

              <TableCell className="tabular-nums">{room.capacity}</TableCell>

              <TableCell>
                <span className="tabular-nums text-sm">
                  {formatMinutesFromSeconds(room.avgProcessTime)}
                </span>
                {room.roomType && room.avgProcessTime !== room.roomType.avgProcessTime && (
                  <span className="ml-1.5 text-xs text-muted-foreground">
                    (default: {formatMinutesFromSeconds(room.roomType.avgProcessTime)})
                  </span>
                )}
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
                    <DropdownMenuItem onClick={() => onEdit(room)}>
                      <Pencil className="mr-2 h-4 w-4" />
                      Edit
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      onClick={() => onDelete(room)}
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