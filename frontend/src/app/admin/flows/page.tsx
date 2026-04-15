'use client';

import { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ArrowLeft, Plus, RefreshCw, Search } from 'lucide-react';
import { useFlows } from '@/features/admin/flow/hooks/useFlows';
import { FlowsTable } from '@/features/admin/flow/components/FlowsTable';
import { FlowFormModal } from '@/features/admin/flow/components/FlowFormModal';
import { FlowDeleteDialog } from '@/features/admin/flow/components/DeleteFlowDialog';
import type {
  Flow,
  FlowFormDto,
} from '@/features/admin/flow/types/flow.type';

export default function FlowsPage() {
  const router = useRouter();
  const { flows, isLoading, error, refresh, createFlow, updateFlow, upsertFlowRooms, deleteFlow } =
    useFlows();

  // ─── Search ───────────────────────────────────────────────────────────────

  const [search, setSearch] = useState('');
  const filteredFlows = flows.filter((f) =>
    f.name.toLowerCase().includes(search.toLowerCase()),
  );

  // ─── Modal state ──────────────────────────────────────────────────────────

  const [modalOpen, setModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<'create' | 'edit'>('create');
  const [editingFlow, setEditingFlow] = useState<Flow | null>(null);
  const [deletingFlow, setDeletingFlow] = useState<Flow | null>(null);

  // ─── Handlers ─────────────────────────────────────────────────────────────

  const openCreate = () => {
    setEditingFlow(null);
    setModalMode('create');
    setModalOpen(true);
  };

  const openEdit = (flow: Flow) => {
    setEditingFlow(flow);
    setModalMode('edit');
    setModalOpen(true);
  };

  const handleSubmit = useCallback(
    async (dto: FlowFormDto) => {
      if (modalMode === 'create') {
        await createFlow({
          name: dto.name,
          rooms: dto.rooms,
          dependencies: dto.dependencies,
        });
      } else if (editingFlow) {
        await updateFlow(editingFlow.id, { name: dto.name });
        await upsertFlowRooms(editingFlow.id, {
          rooms: dto.rooms,
          dependencies: dto.dependencies,
        });
      }
    },
    [modalMode, editingFlow, createFlow, updateFlow, upsertFlowRooms],
  );

  const handleDelete = useCallback(
    async (id: number) => {
      await deleteFlow(id);
    },
    [deleteFlow],
  );

  // ─── Render ───────────────────────────────────────────────────────────────

  return (
    <main className="container mx-auto py-8 px-4 md:px-6 lg:px-8 max-w-7xl space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Flows management</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Create and manage patient flows for the hospital
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button 
            variant="outline" 
            onClick={() => router.push('/admin/dashboard')}
            className="hover:bg-black hover:text-white"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Dashboard
          </Button>
          <Button
            variant="outline"
            size="icon"
            onClick={refresh}
            disabled={isLoading}
            className='hover:bg-black hover:text-white'
            title="Refresh data"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
          <Button 
            variant="outline"
            onClick={openCreate}
            className="hover:bg-black hover:text-white"
          >
            <Plus className="w-4 h-4 mr-2" />
            Add Flow
          </Button>
        </div>
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search by flow name..."
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <span className="text-sm text-muted-foreground ml-auto">
          {!isLoading && `${filteredFlows.length} / ${flows.length} flows`}
        </span>
      </div>

      {/* Error banner */}
      {error && (
        <div className="rounded-md bg-destructive/10 text-destructive text-sm px-4 py-3">
          {error}
        </div>
      )}

      {/* Table */}
      <FlowsTable
        flows={filteredFlows}
        isLoading={isLoading}
        onEdit={openEdit}
        onDelete={setDeletingFlow}
      />

      {/* Create / Edit modal */}
      <FlowFormModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        onSubmit={handleSubmit}
        flow={editingFlow}
        mode={modalMode}
      />

      {/* Delete confirm */}
      <FlowDeleteDialog
        flow={deletingFlow}
        onConfirm={handleDelete}
        onClose={() => setDeletingFlow(null)}
      />
    </main>
  );
}