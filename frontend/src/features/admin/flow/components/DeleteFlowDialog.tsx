'use client';

import { useState } from 'react';
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogCancel,
  AlertDialogAction,
} from '@/components/ui/alert-dialog';
import type { Flow } from '../types/flow.type';

interface Props {
  flow: Flow | null;
  onConfirm: (id: number) => Promise<void>;
  onClose: () => void;
}

export function FlowDeleteDialog({ flow, onConfirm, onClose }: Props) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleConfirm = async () => {
    if (!flow) return;
    setLoading(true);
    setError(null);
    try {
      await onConfirm(flow.id);
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Cannot delete this flow. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AlertDialog open={!!flow} onOpenChange={(v) => !v && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete Flow</AlertDialogTitle>
          <AlertDialogDescription>
            Are you sure you want to delete the flow{' '}
            <span className="font-medium text-foreground">"{flow?.name}"</span>?
            This action cannot be undone and will delete all related visits.
          </AlertDialogDescription>
        </AlertDialogHeader>

        {error && (
          <p className="text-sm text-destructive bg-destructive/10 rounded-md px-3 py-2 mt-2">
            {error}
          </p>
        )}

        <AlertDialogFooter>
          <AlertDialogCancel disabled={loading} onClick={onClose}>
            Cancel
          </AlertDialogCancel>
          <AlertDialogAction
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            disabled={loading}
            onClick={handleConfirm}
          >
            {loading ? 'Deleting...' : 'Delete'}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}