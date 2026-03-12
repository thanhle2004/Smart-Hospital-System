'use client';

import { useSearchParams, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';

interface Patient {
  id: number;
  name: string;
  phone: string;
  email?: string;
}

export default function DashboardPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const patientId = searchParams.get('patientId');

  const [patient, setPatient] = useState<Patient | null>(null);

  useEffect(() => {
    if (!patientId) return;

    const fetchPatient = async () => {
      try {
        const res = await fetch(
          `http://localhost:5000/patient/${patientId}`
        );
        const data = await res.json();
        setPatient(data);
      } catch (error) {
        console.error(error);
      }
    };

    fetchPatient();
  }, [patientId]);

  if (!patientId) {
    return (
      <div className="p-10 text-center">
        <h1 className="text-xl font-semibold text-red-600">
          No patient selected
        </h1>
      </div>
    );
  }

  if (!patient) {
    return (
      <div className="p-10 text-center">
        <h1 className="text-xl font-semibold">
          Loading patient information...
        </h1>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 px-6 py-10">
      <div className="max-w-xl mx-auto space-y-6">

        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold text-blue-900">
            Welcome, {patient.name}
          </h1>
          <p className="text-gray-600">
            Patient Dashboard
          </p>
        </div>

        {/* Info Card */}
        <div className="bg-white rounded-lg p-6 shadow border border-gray-200 space-y-3">
          <h3 className="font-semibold text-gray-900">
            Patient Information
          </h3>

          <div className="flex justify-between text-sm">
            <span className="text-gray-500">ID:</span>
            <span>{patient.id}</span>
          </div>

          <div className="flex justify-between text-sm">
            <span className="text-gray-500">Phone:</span>
            <span>{patient.phone}</span>
          </div>

          {patient.email && (
            <div className="flex justify-between text-sm">
              <span className="text-gray-500">Email:</span>
              <span>{patient.email}</span>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="space-y-3">
          <button
            onClick={() => router.push(`/service-selection?patientId=${patient.id}`)}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white h-12 rounded-lg font-semibold"
          >
            Choose Medical Service
          </button>

          <button
            onClick={() => router.push('/medical-records')}
            className="w-full bg-white border border-gray-300 h-12 rounded-lg font-semibold hover:bg-gray-50"
          >
            View Medical Records
          </button>
        </div>
      </div>
    </div>
  );
}