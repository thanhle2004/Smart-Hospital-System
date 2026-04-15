"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { priorityRuleService } from "../services/priority-rule.service";
import {
  CreatePriorityRuleDto,
  PriorityRule,
  UpdatePriorityRuleDto,
} from "../types/priority-rule.type";

export function usePriorityRules() {
  const [rules, setRules] = useState<PriorityRule[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRules = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      const data = await priorityRuleService.getAll();
      setRules(data);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to load rules";
      setError(msg);
      toast.error(msg);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  const createRule = useCallback(
    async (dto: CreatePriorityRuleDto): Promise<boolean> => {
      try {
        const created = await priorityRuleService.create(dto);
        setRules((prev) => [...prev, created]);
        toast.success("Priority rule created successfully");
        return true;
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Failed to create rule";
        toast.error(msg);
        return false;
      }
    },
    []
  );

  const updateRule = useCallback(
    async (id: number, dto: UpdatePriorityRuleDto): Promise<boolean> => {
      try {
        const updated = await priorityRuleService.update(id, dto);
        setRules((prev) => prev.map((r) => (r.id === id ? updated : r)));
        toast.success("Priority rule updated successfully");
        return true;
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Failed to update rule";
        toast.error(msg);
        return false;
      }
    },
    []
  );

  const deleteRule = useCallback(async (id: number): Promise<boolean> => {
    try {
      await priorityRuleService.remove(id);
      setRules((prev) => prev.filter((r) => r.id !== id));
      toast.success("Priority rule deleted");
      return true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to delete rule";
      toast.error(msg);
      return false;
    }
  }, []);

  const toggleActive = useCallback(async (id: number): Promise<boolean> => {
    try {
      const updated = await priorityRuleService.toggleActive(id);
      setRules((prev) => prev.map((r) => (r.id === id ? updated : r)));
      toast.success(
        `Rule ${updated.isActive ? "activated" : "deactivated"} successfully`
      );
      return true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to toggle status";
      toast.error(msg);
      return false;
    }
  }, []);

  return {
    rules,
    isLoading,
    error,
    refetch: fetchRules,
    createRule,
    updateRule,
    deleteRule,
    toggleActive,
  };
}