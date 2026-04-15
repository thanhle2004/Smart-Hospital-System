'use client';

import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { Shield, UserCircle2, BadgeCheck } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
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
import { Textarea } from '@/components/ui/textarea';
import { Separator } from '@/components/ui/separator';
import type { User, CreateUserDto, UpdateUserDto } from '../types/user.type';

type Mode = 'create' | 'edit';

interface UserFormModalProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: CreateUserDto | UpdateUserDto) => Promise<void>;
  mode: Mode;
  user?: User | null;
  loading?: boolean;
}

interface FormValues {
  email: string;
  password: string;
  role: 'ADMIN' | 'DOCTOR';
  isActive: 'ACTIVE' | 'INACTIVE';
  fullName: string;
  avatarUrl: string;
  bio: string;
}

export function UserFormModal({
  open,
  onClose,
  onSubmit,
  mode,
  user,
  loading = false,
}: UserFormModalProps) {
  const {
    register,
    handleSubmit,
    setValue,
    watch,
    reset,
    formState: { errors },
  } = useForm<FormValues>({
    defaultValues: {
      email: '',
      password: '',
      role: 'DOCTOR',
        isActive: 'ACTIVE',
      fullName: '',
        avatarUrl: '',
      bio: '',
    },
  });

  const role = watch('role');
  const isActive = watch('isActive');

  useEffect(() => {
    if (mode === 'edit' && user) {
      reset({
        email: user.email,
        password: '',
        role: user.role,
        isActive: user.isActive ? 'ACTIVE' : 'INACTIVE',
        fullName: user.profile?.fullName ?? '',
        avatarUrl: user.profile?.avatarUrl ?? '',
        bio: user.profile?.bio ?? '',
      });
    } else {
      reset({
        email: '',
        password: '',
        role: 'DOCTOR',
        isActive: 'ACTIVE',
        fullName: '',
        avatarUrl: '',
        bio: '',
      });
    }
  }, [user, mode, reset, open]);

  const onFormSubmit = async (values: FormValues) => {
    if (mode === 'create') {
      const profile =
        values.fullName || values.avatarUrl || values.bio
          ? {
              fullName: values.fullName || undefined,
              avatarUrl: values.avatarUrl || undefined,
              bio: values.bio || undefined,
            }
          : undefined;

      await onSubmit({
        email: values.email,
        password: values.password,
        role: values.role,
        isActive: values.isActive === 'ACTIVE',
        ...(profile ? { profile } : {}),
      } as CreateUserDto);
    } else {
      await onSubmit({
        email: values.email,
        role: values.role,
        isActive: values.isActive === 'ACTIVE',
        fullName: values.fullName || undefined,
        avatarUrl: values.avatarUrl || undefined,
        bio: values.bio || undefined,
      } as UpdateUserDto);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-[640px]">
        <DialogHeader>
          <DialogTitle>
            {mode === 'create' ? 'Create New User' : 'Edit User'}
          </DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit(onFormSubmit)} className="space-y-6 py-2">
          {mode === 'create' && (
            <div className="rounded-xl border bg-muted/30 p-4">
              <div className="flex items-start gap-3">
                <div className="rounded-full bg-primary/10 p-2 text-primary">
                  <BadgeCheck className="h-4 w-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold">Account setup</h3>
                  <p className="text-sm text-muted-foreground">
                    Create the login account and assign access level.
                  </p>
                </div>
              </div>
            </div>
          )}

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="email">Email *</Label>
              <Input
                id="email"
                type="email"
                placeholder="doctor@clinic.com"
                {...register('email', { required: 'Email is required' })}
              />
              {errors.email && (
                <p className="text-xs text-destructive">{errors.email.message}</p>
              )}
            </div>

            {mode === 'create' && (
              <div className="space-y-1.5 sm:col-span-2">
                <Label htmlFor="password">Password *</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="At least 6 characters"
                  {...register('password', {
                    required: 'Password is required',
                    minLength: { value: 6, message: 'Minimum 6 characters' },
                  })}
                />
                {errors.password && (
                  <p className="text-xs text-destructive">
                    {errors.password.message}
                  </p>
                )}
              </div>
            )}

            <div className="space-y-1.5">
              <Label>Role *</Label>
              <Select
                value={role}
                onValueChange={(val) =>
                  setValue('role', val as 'ADMIN' | 'DOCTOR')
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select role" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="DOCTOR">Doctor</SelectItem>
                  <SelectItem value="ADMIN">Admin</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label>Status</Label>
              <Select
                value={isActive}
                onValueChange={(val) =>
                  setValue('isActive', val as 'ACTIVE' | 'INACTIVE')
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ACTIVE">Active</SelectItem>
                  <SelectItem value="INACTIVE">Inactive</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <Separator />

          <div className="rounded-xl border bg-background p-4 space-y-4">
            <div className="flex items-center gap-2">
              <UserCircle2 className="h-4 w-4 text-muted-foreground" />
              <h3 className="text-sm font-semibold">Profile details</h3>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5 sm:col-span-2">
                <Label htmlFor="fullName">Full Name</Label>
                <Input
                  id="fullName"
                  placeholder="Le Huynh Thanh"
                  {...register('fullName')}
                />
              </div>

              <div className="space-y-1.5 sm:col-span-2">
                <Label htmlFor="avatarUrl">Avatar URL</Label>
                <Input
                  id="avatarUrl"
                  type="url"
                  placeholder="https://example.com/avatar.png"
                  {...register('avatarUrl')}
                />
              </div>

              {mode === 'create' && (
                <div className="space-y-1.5 sm:col-span-2">
                  <Label htmlFor="bio">Bio</Label>
                  <Textarea
                    id="bio"
                    placeholder="Short introduction about the user"
                    rows={4}
                    {...register('bio')}
                  />
                </div>
              )}
            </div>
          </div>

          {mode === 'create' && (
            <div className="rounded-lg border border-dashed bg-muted/20 p-3 text-xs text-muted-foreground">
              <Shield className="mr-1 inline h-3.5 w-3.5" />
              The account will be created immediately with the selected role and
              profile information.
            </div>
          )}

          <DialogFooter className="pt-2">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={loading}>
              {loading
                ? 'Saving...'
                : mode === 'create'
                  ? 'Create User'
                  : 'Save Changes'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}