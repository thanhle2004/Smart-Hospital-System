'use client';

import { Suspense, useState, useEffect } from 'react';
import DashboardView from '@/features/patient/dashboard/components/PatientDashboardView';
import { usePatientDashboard } from '@/features/patient/dashboard/hooks/usePatientDashboard';
import { useActiveVisit } from '@/features/patient/scheduling-result/hooks/useActiveVisit';
import ActiveVisitDialog from '@/features/patient/scheduling-result/components/ActiveVisitDialog';

function DashboardContent() {
  const state = usePatientDashboard();
  const { activeVisit, loading: visitLoading } = useActiveVisit(state.patientId);
  const [showActiveVisitDialog, setShowActiveVisitDialog] = useState(false);

  // Show dialog if patient has active visit and we're not loading
  useEffect(() => {
    if (!visitLoading && activeVisit) {
      setShowActiveVisitDialog(true);
    }
  }, [activeVisit, visitLoading]);

  return (
    <>
      <DashboardView
        patientId={state.patientId}
        patient={state.patient}
        loading={state.loading}
        error={state.error}
        onChooseService={state.goToServiceSelection}
        onViewRecords={state.goToMedicalRecords}
        onEditProfile={state.goToEditProfile}
      />
      <ActiveVisitDialog
        open={showActiveVisitDialog}
        visitId={activeVisit?.id || null}
        onOpenChange={setShowActiveVisitDialog}
      />
    </>
  );
}

export default function DashboardPage() {
  return (
    <Suspense fallback={<div className="p-10 text-center">Loading dashboard...</div>}>
      <DashboardContent />
    </Suspense>
  );
}