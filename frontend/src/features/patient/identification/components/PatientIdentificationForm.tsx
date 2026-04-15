'use client';

import { useState } from 'react';
import { usePatientIdentification } from '../hooks/usePatientIdentification';

export default function PatientIdentificationForm() {
  const { identify, loading } = usePatientIdentification();
  const [phoneNumber, setPhoneNumber] = useState('');

  const formatPhoneNumber = (value: string) => {
    const cleaned = value.replace(/\D/g, '');
    const match = cleaned.match(/^(\d{0,3})(\d{0,3})(\d{0,4})$/);

    if (match) {
      const parts = [match[1], match[2], match[3]].filter(Boolean);
      return parts.join('-');
    }

    return value;
  };

  const handlePhoneChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setPhoneNumber(formatPhoneNumber(e.target.value));
  };

  const cleaned = phoneNumber.replace(/\D/g, '');
  const isValid = cleaned.length >= 10;

  const handleContinue = () => {
    if (isValid) identify(cleaned);
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-blue-50 to-white flex items-center justify-center px-6 py-12">
      <div className="w-full max-w-md space-y-6 bg-white p-8 rounded-xl shadow-sm border border-gray-100">

        {/* Header */}
        <div className="space-y-2 text-center">
          <h1 className="text-2xl font-bold text-blue-900">
            Patient Identification
          </h1>
          <p className="text-gray-600">
            Please enter your phone number to continue
          </p>
        </div>

        {/* Phone Input */}
        <div className="space-y-2">
          <label className="block text-sm font-medium text-gray-700">
            Phone Number
          </label>

          <div className="relative">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M3 5a2 2 0 012-2h2l2 5-3 2a11 11 0 005 5l2-3 5 2v2a2 2 0 01-2 2h-1C8.716 20 4 15.284 4 9V8a2 2 0 01-1-3z"
              />
            </svg>

            <input
              type="tel"
              placeholder="555-123-4567"
              value={phoneNumber}
              onChange={handlePhoneChange}
              maxLength={12}
              className="w-full pl-10 h-12 rounded-lg border border-gray-300
                         focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          <p className="text-sm text-gray-500">
            We'll use this to identify your medical records
          </p>
        </div>

        {/* Info Box */}
        <div className="bg-blue-50 border border-blue-100 rounded-lg p-4">
          <p className="text-sm text-blue-900">
            <strong>Note:</strong> Your phone number is used to retrieve your visit history.
          </p>
        </div>

        {/* Continue Button */}
        <button
          onClick={handleContinue}
          disabled={!isValid || loading}
          className="w-full h-12 bg-blue-600 hover:bg-blue-700 transition-colors
                     text-white font-semibold rounded-lg
                     disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Checking...' : 'Continue'}
        </button>
      </div>
    </div>
  );
}