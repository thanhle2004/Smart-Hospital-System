'use client';

import { useState, useEffect, useCallback } from 'react';
import { flowService } from '../services/flow.service';
import type {
  Flow,
  CreateFlowDto,
  UpdateFlowDto,
  UpsertFlowRoomsDto,
} from '../types/flow.type';

interface UseFlowsReturn {
  flows: Flow[];
  isLoading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  createFlow: (dto: CreateFlowDto) => Promise<Flow>;
  updateFlow: (id: number, dto: UpdateFlowDto) => Promise<Flow>;
  upsertFlowRooms: (id: number, dto: UpsertFlowRoomsDto) => Promise<Flow>;
  deleteFlow: (id: number) => Promise<void>;
}

export function useFlows(): UseFlowsReturn {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await flowService.findAll();
      setFlows(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load flows');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const createFlow = useCallback(async (dto: CreateFlowDto): Promise<Flow> => {
    const created = await flowService.create(dto);
    setFlows((prev) => [...prev, created]);
    return created;
  }, []);

  const updateFlow = useCallback(
    async (id: number, dto: UpdateFlowDto): Promise<Flow> => {
      const updated = await flowService.update(id, dto);
      setFlows((prev) => prev.map((f) => (f.id === id ? updated : f)));
      return updated;
    },
    [],
  );

  const upsertFlowRooms = useCallback(
    async (id: number, dto: UpsertFlowRoomsDto): Promise<Flow> => {
      const updated = await flowService.upsertRooms(id, dto);
      setFlows((prev) => prev.map((f) => (f.id === id ? updated : f)));
      return updated;
    },
    [],
  );

  const deleteFlow = useCallback(async (id: number): Promise<void> => {
    await flowService.remove(id);
    setFlows((prev) => prev.filter((f) => f.id !== id));
  }, []);

  return {
    flows,
    isLoading,
    error,
    refresh,
    createFlow,
    updateFlow,
    upsertFlowRooms,
    deleteFlow,
  };
}