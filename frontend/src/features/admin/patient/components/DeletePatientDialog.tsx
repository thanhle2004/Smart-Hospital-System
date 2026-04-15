'use client';

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import type { Patient } from '../types/patient.type';

interface DeletePatientDialogProps {
  open: boolean;
  patient: Patient | null;
  onClose: () => void;
  onConfirm: () => Promise<void>;
  loading?: boolean;
}

export function DeletePatientDialog({
  open,
  patient,
  onClose,
  onConfirm,
  loading = false,
}: DeletePatientDialogProps) {
  return (
    <AlertDialog open={open} onOpenChange={(o) => !o && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Confirm Delete Patient</AlertDialogTitle>
          <AlertDialogDescription>
            Are you sure you want to delete patient{' '}
            <span className="font-semibold text-foreground">{patient?.name}</span>
            ? This action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={onClose} disabled={loading}>
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction
            onClick={onConfirm}
            disabled={loading}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            {loading ? 'Deleting...' : 'Delete'}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
