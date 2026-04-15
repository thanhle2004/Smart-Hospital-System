"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, Plus, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { RoomTypesTable } from "@/features/admin/room-type/components/RoomTypesTable";
import { RoomTypeFormModal } from "@/features/admin/room-type/components/RoomTypeFormModal";
import { DeleteRoomTypeDialog } from "@/features/admin/room-type/components/DeleteRoomTypeDialog";
import { useRoomTypes } from "@/features/admin/room-type/hooks/useRoomTypes";
import { CreateRoomTypeDto, RoomType } from "@/features/admin/room-type/types/room-type.type";

export default function RoomTypesPage() {
  const router = useRouter();
  const {
    roomTypes,
    isLoading,
    error,
    refetch,
    createRoomType,
    updateRoomType,
    deleteRoomType,
  } = useRoomTypes();

  const [modalOpen, setModalOpen] = useState(false);
  const [editingRoomType, setEditingRoomType] = useState<RoomType | null>(null);
  const [deletingRoomType, setDeletingRoomType] = useState<RoomType | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [search, setSearch] = useState("");

  const openCreateModal = () => {
    setEditingRoomType(null);
    setModalOpen(true);
  };

  const openEditModal = (rt: RoomType) => {
    setEditingRoomType(rt);
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setEditingRoomType(null);
  };

  const handleSubmit = async (dto: CreateRoomTypeDto): Promise<boolean> => {
    setIsSubmitting(true);
    const ok = editingRoomType
      ? await updateRoomType(editingRoomType.id, dto)
      : await createRoomType(dto);
    setIsSubmitting(false);
    return ok;
  };

  const handleDeleteConfirm = async () => {
    if (!deletingRoomType) return;
    setIsDeleting(true);
    await deleteRoomType(deletingRoomType.id);
    setIsDeleting(false);
    setDeletingRoomType(null);
  };

  const filtered = roomTypes.filter(
    (rt) =>
      rt.name.toLowerCase().includes(search.toLowerCase()) ||
      (rt.description ?? "").toLowerCase().includes(search.toLowerCase())
  );

  return (
    <main className="container mx-auto py-8 px-4 md:px-6 lg:px-8 max-w-7xl space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Room Types</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Define room categories with default process time and capacity.
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
            <RefreshCw
              className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`}
            />
          </Button>
          <Button variant="outline" onClick={openCreateModal} className="gap-2 hover:bg-black hover:text-white">
            <Plus className="h-4 w-4" />
            Add Room Type
          </Button>
        </div>
      </div>

      {/* Stats */}
      {!isLoading && !error && (
        <div className="flex items-center gap-6">
          <div className="text-sm text-muted-foreground">
            Total:{" "}
            <span className="font-medium text-foreground">
              {roomTypes.length}
            </span>
          </div>
          <div className="text-sm text-muted-foreground">
            Avg capacity:{" "}
            <span className="font-medium text-foreground">
              {roomTypes.length > 0
                ? Math.round(
                    roomTypes.reduce((s, rt) => s + rt.defaultCapacity, 0) /
                      roomTypes.length
                  )
                : 0}
            </span>
          </div>
        </div>
      )}

      {/* Search */}
      {!isLoading && !error && (
        <div>
          <Input
            placeholder="Search by name or description..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="max-w-sm"
          />
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">
          {error}{" "}
          <button
            onClick={refetch}
            className="underline underline-offset-2 ml-1"
          >
            Retry
          </button>
        </div>
      )}

      {/* Table / Skeleton */}
      {isLoading ? (
        <div className="rounded-lg border">
          <div className="p-4 space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        </div>
      ) : (
        <RoomTypesTable
          roomTypes={filtered}
          onEdit={openEditModal}
          onDelete={setDeletingRoomType}
        />
      )}

      {/* Create / Edit Modal */}
      <RoomTypeFormModal
        open={modalOpen}
        onClose={closeModal}
        onSubmit={handleSubmit}
        editingRoomType={editingRoomType}
        isSubmitting={isSubmitting}
      />

      {/* Delete Dialog */}
      <DeleteRoomTypeDialog
        open={!!deletingRoomType}
        roomTypeName={deletingRoomType?.name ?? ""}
        roomCount={deletingRoomType?._count?.rooms}
        onCancel={() => setDeletingRoomType(null)}
        onConfirm={handleDeleteConfirm}
        isDeleting={isDeleting}
      />
    </main>
  );
}