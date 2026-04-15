'use client';

import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import type {
  Patient,
  CreatePatientDto,
  UpdatePatientDto,
} from '../types/patient.type';
import type { PatientType } from '@/features/admin/patient-type/types/patient-type.type';

type Mode = 'create' | 'edit';

interface PatientFormModalProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: CreatePatientDto | UpdatePatientDto) => Promise<void>;
  mode: Mode;
  patient?: Patient | null;
  patientTypes: PatientType[];
  loading?: boolean;
}

interface FormValues {
  name: string;
  phone: string;
  email: string;
  yearOfBirth: number;
  patientTypeId: string;
}

const currentYear = new Date().getFullYear();

export function PatientFormModal({
  open,
  onClose,
  onSubmit,
  mode,
  patient,
  patientTypes,
  loading = false,
}: PatientFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    setValue,
    watch,
    formState: { errors },
  } = useForm<FormValues>({
    defaultValues: {
      name: '',
      phone: '',
      email: '',
      yearOfBirth: currentYear - 20,
      patientTypeId: '',
    },
  });

  const selectedPatientTypeId = watch('patientTypeId');

  useEffect(() => {
    if (mode === 'edit' && patient) {
      reset({
        name: patient.name,
        phone: patient.phone,
        email: patient.email ?? '',
        yearOfBirth: patient.yearOfBirth,
        patientTypeId: String(patient.patientTypeId),
      });
      return;
    }

    reset({
      name: '',
      phone: '',
      email: '',
      yearOfBirth: currentYear - 20,
      patientTypeId:
        patientTypes.length > 0 ? String(patientTypes[0].id) : '',
    });
  }, [mode, patient, patientTypes, reset, open]);

  const onFormSubmit = async (values: FormValues) => {
    const payload = {
      name: values.name.trim(),
      phone: values.phone.trim(),
      email: values.email.trim() || undefined,
      yearOfBirth: Number(values.yearOfBirth),
      patientTypeId: Number(values.patientTypeId),
    };

    await onSubmit(
      mode === 'create'
        ? (payload as CreatePatientDto)
        : (payload as UpdatePatientDto),
    );
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-[560px]">
        <DialogHeader>
          <DialogTitle>{mode === 'create' ? 'Create Patient' : 'Edit Patient'}</DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit(onFormSubmit)} className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="name">Full Name *</Label>
            <Input
              id="name"
              placeholder="Nguyen Van A"
              {...register('name', { required: 'Name is required' })}
            />
            {errors.name && (
              <p className="text-xs text-destructive">{errors.name.message}</p>
            )}
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="phone">Phone *</Label>
              <Input
                id="phone"
                placeholder="0901234567"
                {...register('phone', { required: 'Phone is required' })}
              />
              {errors.phone && (
                <p className="text-xs text-destructive">{errors.phone.message}</p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="yearOfBirth">Year of Birth *</Label>
              <Input
                id="yearOfBirth"
                type="number"
                min={1900}
                max={currentYear}
                {...register('yearOfBirth', {
                  required: 'Year of birth is required',
                  valueAsNumber: true,
                  min: { value: 1900, message: 'Minimum year is 1900' },
                  max: {
                    value: currentYear,
                    message: `Maximum year is ${currentYear}`,
                  },
                })}
              />
              {errors.yearOfBirth && (
                <p className="text-xs text-destructive">
                  {errors.yearOfBirth.message}
                </p>
              )}
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              placeholder="patient@example.com"
              {...register('email')}
            />
          </div>

          <div className="space-y-1.5">
            <Label>Patient Type *</Label>
            <Select
              value={selectedPatientTypeId}
              onValueChange={(val) => setValue('patientTypeId', val)}
              disabled={patientTypes.length === 0}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select patient type" />
              </SelectTrigger>
              <SelectContent>
                {patientTypes.map((type) => (
                  <SelectItem key={type.id} value={String(type.id)}>
                    {type.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {!selectedPatientTypeId && (
              <p className="text-xs text-destructive">Patient type is required</p>
            )}
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={loading || !selectedPatientTypeId}>
              {loading
                ? 'Saving...'
                : mode === 'create'
                  ? 'Create Patient'
                  : 'Save Changes'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
