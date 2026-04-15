'use client';

import { useState, useEffect, useCallback } from 'react';
import { userService } from '../services/user.service';
import type { User, CreateUserDto, UpdateUserDto } from '../types/user.type';

export function useUsers() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await userService.getAll();
      setUsers(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch users');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  const createUser = useCallback(
    async (dto: CreateUserDto): Promise<User> => {
      const newUser = await userService.create(dto);
      setUsers((prev) => [...prev, newUser]);
      return newUser;
    },
    [],
  );

  const updateUser = useCallback(
    async (id: string, dto: UpdateUserDto): Promise<User> => {
      const updated = await userService.update(id, dto);
      setUsers((prev) => prev.map((u) => (u.id === id ? updated : u)));
      return updated;
    },
    [],
  );

  const deactivateUser = useCallback(async (id: string): Promise<void> => {
    const updated = await userService.deactivate(id);
    setUsers((prev) => prev.map((u) => (u.id === id ? updated : u)));
  }, []);

  const deleteUser = useCallback(async (id: string): Promise<void> => {
    await userService.delete(id);
    setUsers((prev) => prev.filter((u) => u.id !== id));
  }, []);

  return {
    users,
    loading,
    error,
    refetch: fetchUsers,
    createUser,
    updateUser,
    deactivateUser,
    deleteUser,
  };
}