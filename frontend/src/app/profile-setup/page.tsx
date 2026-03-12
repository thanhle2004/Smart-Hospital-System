'use client';

import { useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

export default function ProfileSetup() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const phoneFromQuery = searchParams.get('phone') || '';

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [phone] = useState(phoneFromQuery);
  const [patientTypeId, setPatientTypeId] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async () => {
    if (!name || !phone) {
      setError('Please fill all required fields');
      return;
    }

    try {
      setLoading(true);
      setError('');

      const res = await fetch('http://localhost:5000/patient', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name,
          email: email || undefined,
          phone,
          patientTypeId,
        }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.message || 'Failed to create patient');
      }

      const patient = await res.json();

      router.push(`/dashboard?patientId=${patient.id}`);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-blue-50 to-white flex items-center justify-center px-6 py-12">
      <div className="w-full max-w-md bg-white p-8 rounded-xl shadow-sm border border-gray-100 space-y-6">

        <div className="text-center">
          <h1 className="text-2xl font-bold text-blue-900">
            New Patient Registration
          </h1>
          <p className="text-gray-600">
            Please complete your profile information
          </p>
        </div>

        {/* Name */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Full Name *
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full h-12 px-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:outline-none"
          />
        </div>

        {/* Email */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Email (optional)
          </label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full h-12 px-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:outline-none"
          />
        </div>

        {/* Phone */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Phone Number
          </label>
          <input
            type="text"
            value={phone}
            disabled
            className="w-full h-12 px-3 rounded-lg bg-gray-100 border border-gray-300"
          />
        </div>

        {/* Patient Type */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Patient Type
          </label>
          <select
            value={patientTypeId}
            onChange={(e) => setPatientTypeId(Number(e.target.value))}
            className="w-full h-12 px-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-blue-500 focus:outline-none"
          >
            <option value={1}>Normal</option>
            <option value={2}>VIP</option>
          </select>
        </div>

        {/* Error */}
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 p-3 rounded-lg text-sm">
            {error}
          </div>
        )}

        {/* Button */}
        <button
          onClick={handleSubmit}
          disabled={loading}
          className="w-full h-12 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-semibold transition disabled:opacity-50"
        >
          {loading ? 'Creating...' : 'Create Profile'}
        </button>
      </div>
    </div>
  );
}