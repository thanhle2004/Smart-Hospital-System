'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { ArrowLeft, Plus, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { usePatientTypes } from '@/features/admin/patient-type/hooks/usePatientType';
import { PatientTypeTable } from '@/features/admin/patient-type/components/PatientTypeTable';
import { PatientTypeFormModal } from '@/features/admin/patient-type/components/PatientTypeFormModal';
import { DeleteConfirmDialog } from '@/features/admin/patient-type/components/DeleteConfirmDialog';
import { PatientType, CreatePatientTypePayload } from '@/features/admin/patient-type/types/patient-type.type';
import { Toaster } from 'sonner';

export default function PatientTypePage() {
  const router = useRouter();
  const { patientTypes, isLoading, refetch, create, update, remove, toggleActive } =
    usePatientTypes();

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<PatientType | null>(null);
  const [deletingItem, setDeletingItem] = useState<PatientType | null>(null);

  const handleOpenCreate = () => {
    setEditingItem(null);
    setIsModalOpen(true);
  };

  const handleOpenEdit = (item: PatientType) => {
    setEditingItem(item);
    setIsModalOpen(true);
  };

  const handleCloseModal = () => {
    setIsModalOpen(false);
    setEditingItem(null);
  };

  const handleSubmit = async (payload: CreatePatientTypePayload): Promise<boolean> => {
    if (editingItem) {
      return update(editingItem.id, payload);
    }
    return create(payload);
  };

  return (
    <>
      <Toaster richColors position="top-right" />

      <main className="container mx-auto py-8 px-4 md:px-6 lg:px-8 max-w-7xl space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Patient Types Management</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Create and manage patient types for the hospital
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => router.push('/admin/dashboard')} className="hover:bg-black hover:text-white">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Dashboard
            </Button>
            <Button
              variant="outline"
              size="icon"
              onClick={refetch}
              disabled={isLoading}
              aria-label="Refresh"
              className="hover:bg-black hover:text-white"
            >
              <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
            </Button>
            <Button variant="outline" onClick={handleOpenCreate} className="gap-2 hover:bg-black hover:text-white">
              <Plus className="h-4 w-4" />
              Add Patient Type
            </Button>
          </div>
        </div>

        {/* Stats bar */}
        <div className="flex items-center gap-6 text-sm text-muted-foreground">
          <span>
            Total:{' '}
            <span className="font-semibold text-foreground">{patientTypes.length}</span>
          </span>
          <span>
            Active:{' '}
            <span className="font-semibold text-foreground">
              {patientTypes.filter((p) => p.isActive).length}
            </span>
          </span>
          <span>
            Inactive:{' '}
            <span className="font-semibold text-foreground">
              {patientTypes.filter((p) => !p.isActive).length}
            </span>
          </span>
        </div>

        {/* Table */}
        <PatientTypeTable
          data={patientTypes}
          isLoading={isLoading}
          onEdit={handleOpenEdit}
          onDelete={setDeletingItem}
          onToggleActive={toggleActive}
        />
      </main>

      {/* Form Modal */}
      <PatientTypeFormModal
        open={isModalOpen}
        onClose={handleCloseModal}
        onSubmit={handleSubmit}
        editingItem={editingItem}
      />

      {/* Delete Confirm */}
      <DeleteConfirmDialog
        item={deletingItem}
        onConfirm={remove}
        onClose={() => setDeletingItem(null)}
      />
    </>
  );
}