'use client';

import HospitalEntryView from '@/features/patient/entry/components/HospitalEntryView';
import { useHospitalEntry } from '@/features/patient/entry/hooks/useHospitalEntry';

export default function HospitalEntry() {
  const { goToIdentification } = useHospitalEntry();

  return (
    <HospitalEntryView onContinue={goToIdentification} />
  );
}