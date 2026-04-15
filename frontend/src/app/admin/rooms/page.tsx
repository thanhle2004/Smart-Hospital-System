"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, Plus, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { RoomsTable } from "@/features/admin/room/components/RoomsTable";
import { RoomFormModal } from "@/features/admin/room/components/RoomFormModal";
import { DeleteRoomDialog } from "@/features/admin/room/components/DeleteRoomDialog";
import { useRooms } from "@/features/admin/room/hooks/useRooms";
import { useRoomTypes } from "@/features/admin/room/hooks/useRoomTypes";
import { CreateRoomDto, Room, UpdateRoomDto } from "@/features/admin/room/types/room.type";

export default function RoomsPage() {
  const router = useRouter();
  const { rooms, isLoading, error, refetch, createRoom, updateRoom, deleteRoom } =
    useRooms();
  const { roomTypes } = useRoomTypes();

  const [modalOpen, setModalOpen] = useState(false);
  const [editingRoom, setEditingRoom] = useState<Room | null>(null);
  const [deletingRoom, setDeletingRoom] = useState<Room | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  // Filters
  const [search, setSearch] = useState("");
  const [filterTypeId, setFilterTypeId] = useState<string>("all");

  const openCreateModal = () => {
    setEditingRoom(null);
    setModalOpen(true);
  };

  const openEditModal = (room: Room) => {
    setEditingRoom(room);
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setEditingRoom(null);
  };

  const handleSubmit = async (dto: CreateRoomDto | UpdateRoomDto): Promise<boolean> => {
    setIsSubmitting(true);
    const ok = editingRoom
      ? await updateRoom(editingRoom.id, dto as UpdateRoomDto)
      : await createRoom(dto as CreateRoomDto);
    setIsSubmitting(false);
    return ok;
  };

  const handleDeleteConfirm = async () => {
    if (!deletingRoom) return;
    setIsDeleting(true);
    await deleteRoom(deletingRoom.id);
    setIsDeleting(false);
    setDeletingRoom(null);
  };

  const filteredRooms = rooms.filter((room) => {
    const matchesSearch =
      room.name.toLowerCase().includes(search.toLowerCase()) ||
      String(room.roomNumber).includes(search);
    const matchesType =
      filterTypeId === "all"
        ? true
        : filterTypeId === "none"
          ? room.roomTypeId == null
          : room.roomTypeId === Number(filterTypeId);
    return matchesSearch && matchesType;
  });

  return (
    <main className="container mx-auto py-8 px-4 md:px-6 lg:px-8 max-w-7xl space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Rooms</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage physical rooms and their configurations.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => router.push('/admin/dashboard')} className="hover:bg-black hover:text-white">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Dashboard
          </Button>
          <Button
            variant="outline"
            size="icon"
            onClick={refetch}
            disabled={isLoading}
            title="Refresh"
            className="hover:bg-black hover:text-white"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
          </Button>
          <Button variant="outline" onClick={openCreateModal} className="gap-2 hover:bg-black hover:text-white">
            <Plus className="h-4 w-4" />
            Add Room
          </Button>
        </div>
      </div>

      {/* Stats */}
      {!isLoading && !error && (
        <div className="flex items-center gap-6">
          <div className="text-sm text-muted-foreground">
            Total:{" "}
            <span className="font-medium text-foreground">{rooms.length}</span>
          </div>
          <div className="text-sm text-muted-foreground">
            Types:{" "}
            <span className="font-medium text-foreground">
              {new Set(rooms.map((r) => r.roomTypeId).filter((id): id is number => id != null)).size}
            </span>
          </div>
          <div className="text-sm text-muted-foreground">
            Total capacity:{" "}
            <span className="font-medium text-foreground">
              {rooms.reduce((sum, r) => sum + r.capacity, 0)}
            </span>
          </div>
        </div>
      )}

      {/* Filters */}
      {!isLoading && !error && (
        <div className="flex flex-col sm:flex-row gap-3">
          <Input
            placeholder="Search by name or room number..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="sm:max-w-xs"
          />
          <Select value={filterTypeId} onValueChange={setFilterTypeId}>
            <SelectTrigger className="sm:max-w-[200px]">
              <SelectValue placeholder="All room types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All room types</SelectItem>
              <SelectItem value="none">Unassigned</SelectItem>
              {roomTypes.map((rt) => (
                <SelectItem key={rt.id} value={String(rt.id)}>
                  {rt.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
          {error}{" "}
          <button onClick={refetch} className="underline underline-offset-2 ml-1">
            Retry
          </button>
        </div>
      )}

      {/* Table / Skeleton */}
      {isLoading ? (
        <div className="rounded-lg border">
          <div className="p-4 space-y-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        </div>
      ) : (
        <RoomsTable
          rooms={filteredRooms}
          onEdit={openEditModal}
          onDelete={setDeletingRoom}
        />
      )}

      {/* Create / Edit Modal */}
      <RoomFormModal
        open={modalOpen}
        onClose={closeModal}
        onSubmit={handleSubmit}
        editingRoom={editingRoom}
        roomTypes={roomTypes}
        isSubmitting={isSubmitting}
      />

      {/* Delete Dialog */}
      <DeleteRoomDialog
        open={!!deletingRoom}
        roomName={deletingRoom?.name ?? ""}
        onCancel={() => setDeletingRoom(null)}
        onConfirm={handleDeleteConfirm}
        isDeleting={isDeleting}
      />
    </main>
  );
}