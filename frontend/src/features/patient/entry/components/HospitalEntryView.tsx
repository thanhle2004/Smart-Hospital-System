'use client';

import Image from "next/image";

interface Props {
  onContinue: () => void;
}

export default function HospitalEntryView({ onContinue }: Props) {
  return (
    <div className="min-h-screen bg-gradient-to-b from-blue-50 to-white flex flex-col items-center justify-center px-6 py-12">
      <div className="w-full max-w-md space-y-8 text-center">

        <div className="flex justify-center">
          <div className="w-20 h-20 rounded-2xl overflow-hidden shadow-lg">
            <Image
              src="https://upload.wikimedia.org/wikipedia/vi/2/29/Logo-HCMIU.svg"
              alt="Logo"
              width={80}
              height={80}
              className="rounded-2xl object-cover"
            />
          </div>
        </div>

        <div className="space-y-2">
          <h1 className="text-2xl font-bold text-blue-900">
            Chilling Cat
          </h1>
          <p className="text-gray-600">
            Welcome to our patient portal
          </p>
        </div>

        <div className="bg-white rounded-lg p-6 shadow-sm border border-gray-100 space-y-3">
          <p className="text-gray-700 font-medium">
            This portal allows you to:
          </p>
          <ul className="text-gray-600 space-y-2 text-left">
            <li className="flex items-start gap-2">
              <span className="text-blue-600 mt-1">•</span>
              <span>Check in for your appointment</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-600 mt-1">•</span>
              <span>View your medical records</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-600 mt-1">•</span>
              <span>Select medical services</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-600 mt-1">•</span>
              <span>Track your visit progress</span>
            </li>
          </ul>
        </div>

        <button
          onClick={onContinue}
          className="w-full bg-blue-600 hover:bg-blue-700 transition-colors text-white h-12 rounded-lg font-semibold"
        >
          Continue
        </button>

        <p className="text-gray-500 text-sm">
          Please have your phone number ready
        </p>
      </div>
    </div>
  );
}