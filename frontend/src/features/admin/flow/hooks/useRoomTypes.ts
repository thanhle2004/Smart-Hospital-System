'use client';

import { useState, useEffect } from 'react';
import type { RoomType } from '../types/flow.type';

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:5000';

export function useRoomTypes() {
  const [roomTypes, setRoomTypes] = useState<RoomType[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${BASE_URL}/admin/room-types`, {
          credentials: 'include',
        });
        if (!res.ok) throw new Error('Unable to load room types');
        const data: RoomType[] = await res.json();
        setRoomTypes(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unable to load room types');
      } finally {
        setIsLoading(false);
      }
    };
    load();
  }, []);

  return { roomTypes, isLoading, error };
}