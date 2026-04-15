"use client";

import { useCallback, useEffect, useState } from "react";
import { roomTypeService } from "@/features/admin/room-type/services/room-type.service";
import { RoomType } from "../types/room.type";

export function useRoomTypes() {
  const [roomTypes, setRoomTypes] = useState<RoomType[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const fetch = useCallback(async () => {
    try {
      setIsLoading(true);
      const data = await roomTypeService.getAll();
      setRoomTypes(data);
    } catch {
      // silently fail — room types are secondary data
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { roomTypes, isLoading };
}