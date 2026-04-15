"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { CreateRoomDto, Room, RoomFormValues, RoomType } from "../types/room.type";
import { formatMinutes, formatMinutesFromSeconds } from '@/lib/time';

interface RoomFormModalProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (dto: CreateRoomDto) => Promise<boolean>;
  editingRoom?: Room | null;
  roomTypes: RoomType[];
  isSubmitting?: boolean;
}

const defaultValues: RoomFormValues = {
  name: "",
  roomNumber: "",
  roomTypeId: "__none__",
  avgProcessTime: "0",
};

function roomToFormValues(room: Room): RoomFormValues {
  return {
    name: room.name,
    roomNumber: String(room.roomNumber),
    roomTypeId: room.roomTypeId == null ? "__none__" : String(room.roomTypeId),
    avgProcessTime: String(room.avgProcessTime),
  };
}

function formValuesToDto(values: RoomFormValues): CreateRoomDto {
  const isUnassigned = values.roomTypeId === "__none__";
  return {
    name: values.name.trim(),
    roomNumber: Number(values.roomNumber),
    roomTypeId: isUnassigned ? undefined : Number(values.roomTypeId),
    avgProcessTime: isUnassigned ? 0 : Number(values.avgProcessTime),
  };
}

export function RoomFormModal({
  open,
  onClose,
  onSubmit,
  editingRoom,
  roomTypes,
  isSubmitting = false,
}: RoomFormModalProps) {
  const [values, setValues] = useState<RoomFormValues>(defaultValues);
  const [roomTypeQuery, setRoomTypeQuery] = useState("");
  const [errors, setErrors] = useState<Partial<Record<keyof RoomFormValues, string>>>({});

  const isEdit = !!editingRoom;

  useEffect(() => {
    if (open) {
      setValues(editingRoom ? roomToFormValues(editingRoom) : defaultValues);
      setRoomTypeQuery(editingRoom?.roomType?.name ?? "");
      setErrors({});
    }
  }, [open, editingRoom]);

  const exactMatchedRoomType = useMemo(() => {
    const keyword = roomTypeQuery.trim().toLowerCase();
    if (!keyword) return undefined;
    return roomTypes.find((rt) => rt.name.trim().toLowerCase() === keyword);
  }, [roomTypeQuery, roomTypes]);

  const suggestedRoomTypes = useMemo(() => {
    const keyword = roomTypeQuery.trim().toLowerCase();
    if (!keyword) return roomTypes;
    return roomTypes.filter((rt) => rt.name.toLowerCase().includes(keyword));
  }, [roomTypes, roomTypeQuery]);

  // Auto-fill avgProcessTime when query exactly matches an existing room type
  const handleRoomTypeInputChange = (value: string) => {
    setRoomTypeQuery(value);
    setErrors((prev) => ({ ...prev, roomTypeId: undefined }));

    const keyword = value.trim().toLowerCase();
    const matched = keyword
      ? roomTypes.find((rt) => rt.name.trim().toLowerCase() === keyword)
      : undefined;

    setValues((prev) => ({
      ...prev,
      roomTypeId: matched ? String(matched.id) : "__none__",
      avgProcessTime:
        matched
          ? (prev.avgProcessTime === "" || prev.avgProcessTime === "0" || !isEdit)
            ? String(matched.avgProcessTime)
            : prev.avgProcessTime
          : "0",
    }));
  };

  const set = (field: keyof RoomFormValues, value: string) => {
    setValues((prev) => ({ ...prev, [field]: value }));
    setErrors((prev) => ({ ...prev, [field]: undefined }));
  };

  const validate = (): boolean => {
    const e: typeof errors = {};
    if (!values.name.trim()) e.name = "Room name is required";
    if (!values.roomNumber || Number(values.roomNumber) <= 0)
      e.roomNumber = "Room number must be positive";
    if (roomTypeQuery.trim() && !exactMatchedRoomType) {
      e.roomTypeId = "Room type does not exist. Please select from suggestions or create it first.";
    }
    const hasRoomType = !!exactMatchedRoomType;
    if (hasRoomType && (!values.avgProcessTime || Number(values.avgProcessTime) <= 0)) {
      e.avgProcessTime = "Avg process time is required and must be positive when room type is selected";
    }
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const handleSubmit = async () => {
    if (!validate()) return;
    const ok = await onSubmit(formValuesToDto(values));
    if (ok) onClose();
  };

  const selectedRoomType = exactMatchedRoomType;
  const roomTypeNeedsCreate = roomTypeQuery.trim().length > 0 && !exactMatchedRoomType;

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit Room" : "Add Room"}</DialogTitle>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          {/* Name */}
          <div className="grid gap-1.5">
            <Label htmlFor="name">
              Room Name <span className="text-destructive">*</span>
            </Label>
            <Input
              id="name"
              placeholder="e.g. Consultation Room A"
              value={values.name}
              onChange={(e) => set("name", e.target.value)}
            />
            {errors.name && (
              <p className="text-xs text-destructive">{errors.name}</p>
            )}
          </div>

          <div className="grid gap-1.5">
            <Label htmlFor="roomNumber">
              Room Number <span className="text-destructive">*</span>
            </Label>
            <Input
              id="roomNumber"
              type="number"
              min={1}
              placeholder="e.g. 101"
              value={values.roomNumber}
              onChange={(e) => set("roomNumber", e.target.value)}
            />
            {errors.roomNumber && (
              <p className="text-xs text-destructive">{errors.roomNumber}</p>
            )}
            <p className="text-xs text-muted-foreground">
              Capacity is automatically calculated from active doctors in this room.
            </p>
          </div>

          {/* Room Type */}
          <div className="grid gap-1.5">
            <Label>Room Type (optional)</Label>
            <Input
              list="room-type-suggestions"
              placeholder="Type room type name for auto-suggestion..."
              value={roomTypeQuery}
              onChange={(e) => handleRoomTypeInputChange(e.target.value)}
            />
            <datalist id="room-type-suggestions">
              {suggestedRoomTypes.map((rt) => (
                <option key={rt.id} value={rt.name} />
              ))}
            </datalist>
            <p className="text-xs text-muted-foreground">
              Leave empty to create an unassigned room.
            </p>
            {roomTypeNeedsCreate && (
              <p className="text-xs text-amber-600">
                Room type &quot;{roomTypeQuery.trim()}&quot; does not exist. Please select from suggestions or create it first.
              </p>
            )}
            {selectedRoomType && (
              <p className="text-xs text-muted-foreground">
                Default avg time: {formatMinutesFromSeconds(selectedRoomType.avgProcessTime)}
              </p>
            )}
            {errors.roomTypeId && (
              <p className="text-xs text-destructive">{errors.roomTypeId}</p>
            )}
          </div>

          {/* Avg Process Time */}
          <div className="grid gap-1.5">
            <Label htmlFor="avgProcessTime">
              Avg Process Time (minutes){selectedRoomType ? (
                <span className="text-destructive"> *</span>
              ) : null}
            </Label>
            <Input
              id="avgProcessTime"
              type="number"
              step="1"
              min={selectedRoomType ? 1 : 0}
              placeholder={selectedRoomType ? "e.g. 5" : "0 (auto for unassigned room)"}
              value={values.avgProcessTime}
              onChange={(e) => set("avgProcessTime", e.target.value)}
              disabled={!selectedRoomType}
            />
            {!selectedRoomType && (
              <p className="text-xs text-muted-foreground">
                No room type selected: avg process time will default to 0.
              </p>
            )}
            
            {errors.avgProcessTime && (
              <p className="text-xs text-destructive">{errors.avgProcessTime}</p>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={isSubmitting}>
            {isSubmitting
              ? isEdit
                ? "Saving..."
                : "Creating..."
              : isEdit
                ? "Save changes"
                : "Create room"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}