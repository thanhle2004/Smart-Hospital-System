'use client';

import { Patient } from '../types/patient-dashboard.type';

interface Props {
  patientId: string | null;
  patient: Patient | null;
  loading: boolean;
  error: string;
  onChooseService: () => void;
  onViewRecords: () => void;
  onEditProfile: () => void;
}

export default function DashboardView({
  patientId,
  patient,
  loading,
  error,
  onChooseService,
  onViewRecords,
  onEditProfile,
}: Props) {
  if (loading) {
    return (
      <div className="p-10 text-center">
        <h1 className="text-xl font-semibold">
          Loading patient information...
        </h1>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-10 text-center text-red-600">
        {error}
      </div>
    );
  }

  if (!patient || !patientId) {
    return (
      <div className="p-10 text-center">
        <h1 className="text-xl font-semibold text-red-600">
          No patient information found. Please identify with your phone number first.
        </h1>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 px-6 py-10">
      <div className="max-w-xl mx-auto space-y-6">

        <div>
          <h1 className="text-2xl font-bold text-blue-900">
            Welcome, {patient.name}
          </h1>
          <p className="text-gray-600">
            Patient Dashboard
          </p>
        </div>

        <div className="bg-white rounded-lg p-6 shadow border space-y-3">
          <h3 className="font-semibold">Patient Information</h3>

          <div className="flex justify-between text-sm">
            <span>Year of Birth:</span>
            <span>{patient.yearOfBirth}</span>
          </div>

          <div className="flex justify-between text-sm">
            <span>Phone:</span>
            <span>{patient.phone}</span>
          </div>

          {patient.email && (
            <div className="flex justify-between text-sm">
              <span>Email:</span>
              <span>{patient.email}</span>
            </div>
          )}
        </div>

        <div className="space-y-3">
          <button
            onClick={onEditProfile}
            className="w-full bg-white border h-12 rounded-lg"
          >
            Edit Profile Information
          </button>

          <button
            onClick={onChooseService}
            className="w-full bg-blue-600 text-white h-12 rounded-lg"
          >
            Choose Medical Service
          </button>

          <button
            onClick={onViewRecords}
            className="w-full bg-white border h-12 rounded-lg"
          >
            View Medical Records
          </button>
        </div>
      </div>
    </div>
  );
}