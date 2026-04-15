'use client';

import { Suspense } from 'react';
import PatientProfileEditView from '@/features/patient/profile/components/PatientProfileEditView';
import { usePatientProfileEdit } from '@/features/patient/profile/hooks/usePatientProfileEdit';

function ProfileContent() {
  const state = usePatientProfileEdit();

  return (
    <PatientProfileEditView
      loading={state.loading}
      submitting={state.submitting}
      error={state.error}
      name={state.name}
      email={state.email}
      phone={state.phone}
      yearOfBirth={state.yearOfBirth}
      onNameChange={state.setName}
      onEmailChange={state.setEmail}
      onYearOfBirthChange={state.setYearOfBirth}
      onSubmit={state.submit}
      onBack={state.backToDashboard}
    />
  );
}

export default function PatientProfilePage() {
  return (
    <Suspense fallback={<div className="p-10 text-center">Loading profile...</div>}>
      <ProfileContent />
    </Suspense>
  );
}
