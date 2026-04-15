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
import { PatientType } from '../types/patient-type.type';

interface DeleteConfirmDialogProps {
  item: PatientType | null;
  onConfirm: (id: number) => Promise<boolean>;
  onClose: () => void;
}

export function DeleteConfirmDialog({
  item,
  onConfirm,
  onClose,
}: DeleteConfirmDialogProps) {
  const handleConfirm = async () => {
    if (!item) return;
    await onConfirm(item.id);
    onClose();
  };

  return (
    <AlertDialog open={!!item} onOpenChange={(v) => !v && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete Patient Type</AlertDialogTitle>
          <AlertDialogDescription>
            Are you sure you want to delete the patient type{' '}
            <span className="font-semibold text-foreground">
              &quot;{item?.name}&quot;
            </span>
            ? This action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={onClose}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={handleConfirm}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            Delete
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}