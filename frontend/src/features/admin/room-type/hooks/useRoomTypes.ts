"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { roomTypeService } from "../services/room-type.service";
import { CreateRoomTypeDto, RoomType, UpdateRoomTypeDto } from "../types/room-type.type";

export function useRoomTypes() {
  const [roomTypes, setRoomTypes] = useState<RoomType[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRoomTypes = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      const data = await roomTypeService.getAll();
      setRoomTypes(data);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to load room types";
      setError(msg);
      toast.error(msg);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRoomTypes();
  }, [fetchRoomTypes]);

  const createRoomType = useCallback(
    async (dto: CreateRoomTypeDto): Promise<boolean> => {
      try {
        const created = await roomTypeService.create(dto);
        setRoomTypes((prev) => [...prev, created]);
        toast.success("Room type created successfully");
        return true;
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Failed to create room type");
        return false;
      }
    },
    []
  );

  const updateRoomType = useCallback(
    async (id: number, dto: UpdateRoomTypeDto): Promise<boolean> => {
      try {
        const updated = await roomTypeService.update(id, dto);
        setRoomTypes((prev) => prev.map((rt) => (rt.id === id ? updated : rt)));
        toast.success("Room type updated successfully");
        return true;
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Failed to update room type");
        return false;
      }
    },
    []
  );

  const deleteRoomType = useCallback(async (id: number): Promise<boolean> => {
    try {
      await roomTypeService.remove(id);
      setRoomTypes((prev) => prev.filter((rt) => rt.id !== id));
      toast.success("Room type deleted");
      return true;
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to delete room type");
      return false;
    }
  }, []);

  return {
    roomTypes,
    isLoading,
    error,
    refetch: fetchRoomTypes,
    createRoomType,
    updateRoomType,
    deleteRoomType,
  };
}