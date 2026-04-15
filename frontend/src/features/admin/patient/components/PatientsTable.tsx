'use client';

import { format } from 'date-fns';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type { Patient } from '../types/patient.type';

interface PatientsTableProps {
  patients: Patient[];
  showSensitive: boolean;
}

function maskPhone(phone: string): string {
  if (!phone) return '—';
  if (phone.length <= 6) return '*'.repeat(phone.length);

  const head = phone.slice(0, 3);
  const tail = phone.slice(-3);
  const stars = '*'.repeat(Math.max(4, phone.length - 6));
  return `${head}${stars}${tail}`;
}

function maskEmail(email: string | null | undefined): string {
  if (!email) return '—';

  const [local, domain] = email.split('@');
  if (!domain) return '—';

  const first = local?.[0] ?? '*';
  return `${first}***@${domain}`;
}

export function PatientsTable({ patients, showSensitive }: PatientsTableProps) {
  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[60px]">#</TableHead>
            <TableHead className="w-[240px]">Name</TableHead>
            <TableHead>Phone</TableHead>
            <TableHead>Email</TableHead>
            <TableHead className="w-[110px]">Year</TableHead>
            <TableHead className="w-[180px]">Patient Type</TableHead>
            <TableHead className="w-[130px]">Created</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {patients.length === 0 && (
            <TableRow>
              <TableCell colSpan={7} className="h-24 text-center text-muted-foreground">
                No patients found.
              </TableCell>
            </TableRow>
          )}
          {patients.map((patient, index) => (
            <TableRow key={patient.id}>
              <TableCell className="text-muted-foreground text-sm tabular-nums">
                {index + 1}
              </TableCell>
              <TableCell className="font-medium">{patient.name}</TableCell>
              <TableCell>{showSensitive ? patient.phone : maskPhone(patient.phone)}</TableCell>
              <TableCell>
                {showSensitive ? patient.email ?? '—' : maskEmail(patient.email)}
              </TableCell>
              <TableCell>{patient.yearOfBirth}</TableCell>
              <TableCell>{patient.patientType?.name ?? '—'}</TableCell>
              <TableCell className="text-sm text-muted-foreground">
                {format(new Date(patient.createdAt), 'dd/MM/yyyy')}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
