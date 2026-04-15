'use client';

import { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';
import { ArrowLeft, Plus, RefreshCw, Users } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { useUsers } from '@/features/admin/user/hooks/useUser';
import { UserTable } from '@/features/admin/user/components/UsersTable';
import { UserFormModal } from '@/features/admin/user/components/UserFormModal';
import { DeleteConfirmDialog } from '@/features/admin/user/components/DeleteConfirmDialog';
import type { User, CreateUserDto, UpdateUserDto } from '@/features/admin/user/types/user.type';

type ModalMode = 'create' | 'edit';

export default function UsersPage() {
  const router = useRouter();
  const {
    users,
    loading,
    error,
    refetch,
    createUser,
    updateUser,
    deactivateUser,
    deleteUser,
  } = useUsers();

  // Modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<ModalMode>('create');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [modalLoading, setModalLoading] = useState(false);

  // Delete dialog state
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<User | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  // Filters
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState<'ALL' | 'ADMIN' | 'DOCTOR'>(
    'ALL',
  );
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ACTIVE' | 'INACTIVE'>('ALL');

  // Filtered users
  const filteredUsers = users.filter((u) => {
    const matchSearch =
      search === '' ||
      u.email.toLowerCase().includes(search.toLowerCase()) ||
      (u.profile?.fullName ?? '')
        .toLowerCase()
        .includes(search.toLowerCase());
    const matchRole = roleFilter === 'ALL' || u.role === roleFilter;
    const matchStatus =
      statusFilter === 'ALL' ||
      (statusFilter === 'ACTIVE' ? u.isActive : !u.isActive);
    return matchSearch && matchRole && matchStatus;
  });

  // Handlers
  const handleOpenCreate = () => {
    setModalMode('create');
    setSelectedUser(null);
    setModalOpen(true);
  };

  const handleOpenEdit = (user: User) => {
    setModalMode('edit');
    setSelectedUser(user);
    setModalOpen(true);
  };

  const handleOpenDelete = (user: User) => {
    setDeleteTarget(user);
    setDeleteOpen(true);
  };

  const handleDeactivate = useCallback(
    async (user: User) => {
      try {
        await deactivateUser(user.id);
        toast.success(`User deactivated successfully`);
      } catch (err) {
        toast.error(err instanceof Error ? err.message : 'Action failed');
      }
    },
    [deactivateUser],
  );

  const handleModalSubmit = async (data: CreateUserDto | UpdateUserDto) => {
    setModalLoading(true);
    try {
      if (modalMode === 'create') {
        await createUser(data as CreateUserDto);
        toast.success('User created successfully');
      } else if (selectedUser) {
        await updateUser(selectedUser.id, data as UpdateUserDto);
        toast.success('User updated successfully');
      }
      setModalOpen(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Action failed');
    } finally {
      setModalLoading(false);
    }
  };

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return;
    setDeleteLoading(true);
    try {
      await deleteUser(deleteTarget.id);
      toast.success('User deleted successfully');
      setDeleteOpen(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to delete user');
    } finally {
      setDeleteLoading(false);
    }
  };

  return (
    <main className="container mx-auto py-8 px-4 md:px-6 lg:px-8 max-w-7xl space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">
              User Management
            </h1>
            <p className="text-sm text-muted-foreground">
              {users.length} users in the system
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={() => router.push('/admin/dashboard')}
            className="hover:bg-black hover:text-white"
          >
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Dashboard
          </Button>
          <Button
            variant="outline"
            size="icon"
            onClick={refetch}
            disabled={loading}
            className="hover:bg-black hover:text-white"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
          <Button
            variant="outline"
            onClick={handleOpenCreate}
            className="hover:bg-black hover:text-white"
          >
            <Plus className="mr-2 h-4 w-4" />
            Add User
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <Input
          placeholder="Search by name or email..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="sm:max-w-xs"
        />
        <Select
          value={roleFilter}
          onValueChange={(v) => setRoleFilter(v as typeof roleFilter)}
        >
          <SelectTrigger className="sm:w-40">
            <SelectValue placeholder="Role" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="ALL">All Roles</SelectItem>
            <SelectItem value="ADMIN">Admin</SelectItem>
            <SelectItem value="DOCTOR">Doctor</SelectItem>
          </SelectContent>
        </Select>
        <Select
          value={statusFilter}
          onValueChange={(v) => setStatusFilter(v as typeof statusFilter)}
        >
          <SelectTrigger className="sm:w-44">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="ALL">All Statuses</SelectItem>
            <SelectItem value="ACTIVE">Active</SelectItem>
            <SelectItem value="INACTIVE">Inactive</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Error state */}
      {error && (
        <div className="rounded-md bg-destructive/10 border border-destructive/20 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {/* Table / Skeleton */}
      {loading ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-14 w-full rounded-md" />
          ))}
        </div>
      ) : (
        <UserTable
          users={filteredUsers}
          onEdit={handleOpenEdit}
          onDelete={handleOpenDelete}
          onDeactivate={handleDeactivate}
        />
      )}

      {/* Modals */}
      <UserFormModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        onSubmit={handleModalSubmit}
        mode={modalMode}
        user={selectedUser}
        loading={modalLoading}
      />

      <DeleteConfirmDialog
        open={deleteOpen}
        user={deleteTarget}
        onClose={() => setDeleteOpen(false)}
        onConfirm={handleDeleteConfirm}
        loading={deleteLoading}
      />
    </main>
  );
}