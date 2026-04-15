'use client';

import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import {
  PatientType,
  CreatePatientTypePayload,
} from '../types/patient-type.type';

interface PatientTypeFormModalProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (payload: CreatePatientTypePayload) => Promise<boolean>;
  editingItem?: PatientType | null;
}

type FormValues = CreatePatientTypePayload;

export function PatientTypeFormModal({
  open,
  onClose,
  onSubmit,
  editingItem,
}: PatientTypeFormModalProps) {
  const isEditing = !!editingItem;

  const {
    register,
    handleSubmit,
    reset,
    setValue,
    watch,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({
    defaultValues: {
      code: '',
      name: '',
      description: '',
      basePriority: undefined,
      isActive: true,
    },
  });

  const isActiveValue = watch('isActive');

  useEffect(() => {
    if (open) {
      if (editingItem) {
        reset({
          code: editingItem.code,
          name: editingItem.name,
          description: editingItem.description ?? '',
          basePriority: editingItem.basePriority ?? undefined,
          isActive: editingItem.isActive,
        });
      } else {
        reset({
          code: '',
          name: '',
          description: '',
          basePriority: undefined,
          isActive: true,
        });
      }
    }
  }, [open, editingItem, reset]);

  const handleFormSubmit = async (values: FormValues) => {
    const payload: CreatePatientTypePayload = {
      code: values.code.trim(),
      name: values.name.trim(),
      description: values.description?.trim() || undefined,
      basePriority:
        values.basePriority !== undefined && values.basePriority !== null
          ? Number(values.basePriority)
          : undefined,
      isActive: values.isActive,
    };
    const ok = await onSubmit(payload);
    if (ok) onClose();
  };

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle className="text-lg font-semibold">
            {isEditing ? 'Edit Patient Type' : 'Create Patient Type'}
          </DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit(handleFormSubmit)} className="space-y-4 py-2">
          {/* Code */}
          <div className="space-y-1.5">
            <Label htmlFor="code">
              Code <span className="text-destructive">*</span>
            </Label>
            <Input
              id="code"
              placeholder="VD: SENIOR, EMERGENCY..."
              {...register('code', { required: 'Please enter a code' })}
            />
            {errors.code && (
              <p className="text-xs text-destructive">{errors.code.message}</p>
            )}
          </div>

          {/* Name */}
          <div className="space-y-1.5">
            <Label htmlFor="name">
              Name <span className="text-destructive">*</span>
            </Label>
            <Input
              id="name"
              placeholder="VD: Senior Patient, Emergency Patient..."
              {...register('name', { required: 'Please enter a name' })}
            />
            {errors.name && (
              <p className="text-xs text-destructive">{errors.name.message}</p>
            )}
          </div>

          {/* Description */}
          <div className="space-y-1.5">
            <Label htmlFor="description">Description</Label>
            <Textarea
              id="description"
              placeholder="Additional description for this patient type (optional)"
              rows={3}
              {...register('description')}
            />
          </div>

          {/* Base Priority */}
          <div className="space-y-1.5">
            <Label htmlFor="basePriority">Base Priority</Label>
            <Input
              id="basePriority"
              type="number"
              min={0}
              placeholder="VD: 10"
              {...register('basePriority', {
                setValueAs: (v: unknown) => (v === '' ? undefined : Number(v)),
                min: { value: 0, message: 'Value must be ≥ 0' },
              })}
            />
            {errors.basePriority && (
              <p className="text-xs text-destructive">
                {errors.basePriority.message}
              </p>
            )}
          </div>

          {/* isActive */}
          <div className="flex items-center justify-between rounded-lg border px-4 py-3">
            <div>
              <p className="text-sm font-medium">Activate</p>
              <p className="text-xs text-muted-foreground">
                The patient type will be displayed in the system
              </p>
            </div>
            <Switch
              checked={isActiveValue}
              onCheckedChange={(val) => setValue('isActive', val)}
            />
          </div>

          <DialogFooter className="pt-2">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting
                ? isEditing
                  ? 'Saving...'
                  : 'Creating...'
                : isEditing
                  ? 'Save Changes'
                  : 'Create New'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}