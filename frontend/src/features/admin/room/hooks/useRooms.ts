"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { roomService } from "../services/room.service";
import { CreateRoomDto, Room, UpdateRoomDto } from "../types/room.type";

export function useRooms() {
  const [rooms, setRooms] = useState<Room[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRooms = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      const data = await roomService.getAll();
      setRooms(data);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to load rooms";
      setError(msg);
      toast.error(msg);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRooms();
  }, [fetchRooms]);

  const createRoom = useCallback(async (dto: CreateRoomDto): Promise<boolean> => {
    try {
      const created = await roomService.create(dto);
      setRooms((prev) => [...prev, created]);
      toast.success("Room created successfully");
      return true;
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to create room");
      return false;
    }
  }, []);

  const updateRoom = useCallback(
    async (id: number, dto: UpdateRoomDto): Promise<boolean> => {
      try {
        const updated = await roomService.update(id, dto);
        setRooms((prev) => prev.map((r) => (r.id === id ? updated : r)));
        toast.success("Room updated successfully");
        return true;
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Failed to update room");
        return false;
      }
    },
    []
  );

  const deleteRoom = useCallback(async (id: number): Promise<boolean> => {
    try {
      await roomService.remove(id);
      setRooms((prev) => prev.filter((r) => r.id !== id));
      toast.success("Room deleted");
      return true;
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to delete room");
      return false;
    }
  }, []);

  return {
    rooms,
    isLoading,
    error,
    refetch: fetchRooms,
    createRoom,
    updateRoom,
    deleteRoom,
  };
}