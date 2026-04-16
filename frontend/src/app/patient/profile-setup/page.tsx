'use client';

import { Suspense } from 'react';
import ProfileSetupView from '@/features/patient/profile-setup/components/ProfileSetupView';
import { useProfileSetup } from '@/features/patient/profile-setup/hooks/useProfileSetup';

function ProfileSetupContent() {
  const state = useProfileSetup();

  return (
    <ProfileSetupView
      name={state.name}
      email={state.email}
      phone={state.phone}
      loading={state.loading}
      error={state.error}
      onNameChange={state.setName}
      onEmailChange={state.setEmail}
      onYearOfBirthChange={state.setYearOfBirth}
      onSubmit={state.submit}
    />
  );
}

export default function ProfileSetup() {
  return (
    <Suspense fallback={<div className="p-10 text-center">Loading profile setup...</div>}>
      <ProfileSetupContent />
    </Suspense>
  );
}