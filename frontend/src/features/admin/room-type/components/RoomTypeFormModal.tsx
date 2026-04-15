"use client";

import { useEffect, useState } from "react";
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
import { Textarea } from "@/components/ui/textarea";
import {
  CreateRoomTypeDto,
  RoomType,
  RoomTypeFormValues,
} from "../types/room-type.type";
import { formatMinutes } from '@/lib/time';

interface RoomTypeFormModalProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (dto: CreateRoomTypeDto) => Promise<boolean>;
  editingRoomType?: RoomType | null;
  isSubmitting?: boolean;
}

const defaultValues: RoomTypeFormValues = {
  name: "",
  description: "",
  avgProcessTime: "",
  defaultCapacity: "",
};

function toFormValues(rt: RoomType): RoomTypeFormValues {
  return {
    name: rt.name,
    description: rt.description ?? "",
    avgProcessTime: String(rt.avgProcessTime),
    defaultCapacity: String(rt.defaultCapacity),
  };
}

function toDto(values: RoomTypeFormValues): CreateRoomTypeDto {
  return {
    name: values.name.trim(),
    description: values.description.trim() || undefined,
    avgProcessTime: Number(values.avgProcessTime),
    defaultCapacity: Number(values.defaultCapacity),
  };
}

export function RoomTypeFormModal({
  open,
  onClose,
  onSubmit,
  editingRoomType,
  isSubmitting = false,
}: RoomTypeFormModalProps) {
  const [values, setValues] = useState<RoomTypeFormValues>(defaultValues);
  const [errors, setErrors] = useState<
    Partial<Record<keyof RoomTypeFormValues, string>>
  >({});

  const isEdit = !!editingRoomType;

  useEffect(() => {
    if (open) {
      setValues(editingRoomType ? toFormValues(editingRoomType) : defaultValues);
      setErrors({});
    }
  }, [open, editingRoomType]);

  const set = (field: keyof RoomTypeFormValues, value: string) => {
    setValues((prev) => ({ ...prev, [field]: value }));
    setErrors((prev) => ({ ...prev, [field]: undefined }));
  };

  const validate = (): boolean => {
    const e: typeof errors = {};
    if (!values.name.trim()) e.name = "Name is required";
    if (!values.avgProcessTime || Number(values.avgProcessTime) <= 0)
      e.avgProcessTime = "Must be a positive number (minutes)";
    if (!values.defaultCapacity || Number(values.defaultCapacity) <= 0)
      e.defaultCapacity = "Must be a positive number";
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const handleSubmit = async () => {
    if (!validate()) return;
    const ok = await onSubmit(toDto(values));
    if (ok) onClose();
  };

  const minutes = Number(values.avgProcessTime);

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle>
            {isEdit ? "Edit Room Type" : "Add Room Type"}
          </DialogTitle>
        </DialogHeader>

        <div className="grid gap-4 py-2">
          {/* Name */}
          <div className="grid gap-1.5">
            <Label htmlFor="name">
              Name <span className="text-destructive">*</span>
            </Label>
            <Input
              id="name"
              placeholder="e.g. Consultation, Lab, Radiology"
              value={values.name}
              onChange={(e) => set("name", e.target.value)}
            />
            {errors.name && (
              <p className="text-xs text-destructive">{errors.name}</p>
            )}
          </div>

          {/* Description */}
          <div className="grid gap-1.5">
            <Label htmlFor="description">Description</Label>
            <Textarea
              id="description"
              placeholder="Optional description..."
              rows={3}
              value={values.description}
              onChange={(e) => set("description", e.target.value)}
              className="resize-none"
            />
          </div>

          {/* Avg Process Time & Default Capacity */}
          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-1.5">
              <Label htmlFor="avgProcessTime">
                Avg Process Time (minutes) <span className="text-destructive">*</span>
              </Label>
              <Input
                id="avgProcessTime"
                type="number"
                step="1"
                min={1}
                placeholder="e.g. 5"
                value={values.avgProcessTime}
                onChange={(e) => set("avgProcessTime", e.target.value)}
              />
              {minutes > 0 && !errors.avgProcessTime && (
                <p className="text-xs text-muted-foreground">
                  = {formatMinutes(minutes)}
                </p>
              )}
              {errors.avgProcessTime && (
                <p className="text-xs text-destructive">
                  {errors.avgProcessTime}
                </p>
              )}
            </div>

            <div className="grid gap-1.5">
              <Label htmlFor="defaultCapacity">
                Default Capacity <span className="text-destructive">*</span>
              </Label>
              <Input
                id="defaultCapacity"
                type="number"
                min={1}
                placeholder="e.g. 5"
                value={values.defaultCapacity}
                onChange={(e) => set("defaultCapacity", e.target.value)}
              />
              {errors.defaultCapacity && (
                <p className="text-xs text-destructive">
                  {errors.defaultCapacity}
                </p>
              )}
            </div>
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
                : "Create room type"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}