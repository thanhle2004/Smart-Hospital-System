'use client';

import { useRouter } from 'next/navigation';

export function useHospitalEntry() {
  const router = useRouter();

  const goToIdentification = () => {
    router.push('/patient/identify');
  };

  return {
    goToIdentification,
  };
}