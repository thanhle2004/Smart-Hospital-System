'use client';

import { useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import { ArrowLeft, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { authService } from '@/features/auth/services/auth.service';
import { usePatients } from '@/features/admin/patient/hooks/usePatients';
import { usePatientTypes } from '@/features/admin/patient-type/hooks/usePatientType';
import { PatientsTable } from '@/features/admin/patient/components/PatientsTable';

const SENSITIVE_AUTO_HIDE_MS = 5 * 60 * 1000;

export default function PatientsPage() {
  const router = useRouter();
  const {
    patients,
    isLoading,
    error,
    refetch,
  } = usePatients();
  const { patientTypes, refetch: refetchPatientTypes } = usePatientTypes();

  const [search, setSearch] = useState('');
  const [patientTypeFilter, setPatientTypeFilter] = useState<string>('ALL');
  const [showSensitive, setShowSensitive] = useState(false);
  const [verifyDialogOpen, setVerifyDialogOpen] = useState(false);
  const [adminPassword, setAdminPassword] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  useEffect(() => {
    if (!showSensitive) return;

    const timeoutId = window.setTimeout(() => {
      setShowSensitive(false);
    }, SENSITIVE_AUTO_HIDE_MS);

    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [showSensitive]);

  const filteredPatients = useMemo(() => {
    return patients.filter((p) => {
      const q = search.toLowerCase().trim();
      const matchSearch =
        q === '' ||
        p.name.toLowerCase().includes(q) ||
        p.phone.toLowerCase().includes(q) ||
        (p.email ?? '').toLowerCase().includes(q);

      const matchType =
        patientTypeFilter === 'ALL' ||
        String(p.patientTypeId) === patientTypeFilter;

      return matchSearch && matchType;
    });
  }, [patients, search, patientTypeFilter]);

  const handleRefresh = async () => {
    await Promise.all([refetch(), refetchPatientTypes()]);
  };

  const handleOpenVerify = () => {
    setAdminPassword('');
    setVerifyError(null);
    setVerifyDialogOpen(true);
  };

  const handleVerifyPassword = async () => {
    if (!adminPassword.trim()) {
      setVerifyError('Please enter admin password');
      return;
    }

    setIsVerifying(true);
    setVerifyError(null);

    try {
      const result = await authService.verifyPassword(adminPassword);
      if (result.verified) {
        setShowSensitive(true);
        setVerifyDialogOpen(false);
      }
    } catch (err) {
      setVerifyError(err instanceof Error ? err.message : 'Password verification failed');
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <main className="container mx-auto py-8 px-4 md:px-6 lg:px-8 max-w-7xl space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Patients Report</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Read-only statistics and reporting for patient records.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={() => router.push('/admin/dashboard')}
            className="hover:bg-black hover:text-white"
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Dashboard
          </Button>

          <Button
            variant="outline"
            size="icon"
            onClick={handleRefresh}
            disabled={isLoading}
            className="hover:bg-black hover:text-white"
            title="Refresh"
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>

          {showSensitive ? (
            <Button
              variant="outline"
              onClick={() => setShowSensitive(false)}
              className="hover:bg-black hover:text-white"
            >
              Hide Sensitive Data
            </Button>
          ) : (
            <Button
              variant="outline"
              onClick={handleOpenVerify}
              className="hover:bg-black hover:text-white"
            >
              Show Sensitive Data
            </Button>
          )}
        </div>
      </div>

      {!isLoading && !error && (
        <div className="flex items-center gap-6 text-sm text-muted-foreground">
          <span>
            Total: <span className="font-semibold text-foreground">{patients.length}</span>
          </span>
          <span>
            Patient types in use:{' '}
            <span className="font-semibold text-foreground">
              {new Set(patients.map((p) => p.patientTypeId)).size}
            </span>
          </span>
          {showSensitive && (
            <span className="text-amber-700">
              Sensitive data will be hidden automatically after 5 minutes.
            </span>
          )}
        </div>
      )}

      <div className="flex flex-col sm:flex-row gap-3">
        <Input
          placeholder="Search by name, phone, or email..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="sm:max-w-xs"
        />

        <Select value={patientTypeFilter} onValueChange={setPatientTypeFilter}>
          <SelectTrigger className="sm:w-[220px]">
            <SelectValue placeholder="Patient type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="ALL">All patient types</SelectItem>
            {patientTypes.map((type) => (
              <SelectItem key={type.id} value={String(type.id)}>
                {type.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {error && (
        <div className="rounded-md bg-destructive/10 border border-destructive/20 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-14 w-full rounded-md" />
          ))}
        </div>
      ) : (
        <PatientsTable patients={filteredPatients} showSensitive={showSensitive} />
      )}

      <Dialog open={verifyDialogOpen} onOpenChange={setVerifyDialogOpen}>
        <DialogContent className="sm:max-w-[420px]">
          <DialogHeader>
            <DialogTitle>Verify Admin Password</DialogTitle>
            <DialogDescription>
              Enter admin password to reveal patient phone and email.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-2">
            <Label htmlFor="admin-password">Password</Label>
            <Input
              id="admin-password"
              type="password"
              value={adminPassword}
              onChange={(e) => setAdminPassword(e.target.value)}
              placeholder="Enter admin password"
            />
            {verifyError && (
              <p className="text-xs text-destructive">{verifyError}</p>
            )}
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setVerifyDialogOpen(false)}
              disabled={isVerifying}
            >
              Cancel
            </Button>
            <Button onClick={handleVerifyPassword} disabled={isVerifying}>
              {isVerifying ? 'Verifying...' : 'Verify'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </main>
  );
}
