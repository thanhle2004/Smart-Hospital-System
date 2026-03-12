'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

interface Flow {
  id: number;
  name: string;
}

export default function ServiceSelectionPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const patientId = searchParams.get('patientId');

  const [flows, setFlows] = useState<Flow[]>([]);
  const [selectedFlowId, setSelectedFlowId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchFlows = async () => {
      try {
        const res = await fetch('http://localhost:5000/flow/simple');
        const data = await res.json();
        setFlows(data);
      } catch (error) {
        console.error(error);
      } finally {
        setLoading(false);
      }
    };

    fetchFlows();
  }, []);

  const handleConfirm = async () => {
    if (!selectedFlowId || !patientId) return;

    const res = await fetch('http://localhost:5000/visit/check-in', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            patientId: Number(patientId),
            flowId: selectedFlowId,
        }),
    });

    if (!res.ok) {
        console.error('API ERROR');
        return;
    }

    const data = await res.json();
    console.log('CHECKIN RESULT:', data);

    router.push(`/scheduling-result?visitId=${data.id}`);
    };

  if (loading) {
    return (
      <div className="p-10 text-center">
        Loading medical services...
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 px-6 py-8">
      <div className="max-w-md mx-auto space-y-6">

        {/* Header */}
        <div>
          <h1 className="text-xl font-bold text-blue-900">
            Medical Services
          </h1>
          <p className="text-gray-600 text-sm">
            Select a department
          </p>
        </div>

        {/* Flow List */}
        <div className="space-y-3">
          {flows.map((flow) => (
            <button
              key={flow.id}
              onClick={() => setSelectedFlowId(flow.id)}
              className={`w-full bg-white rounded-lg p-4 border-2 text-left transition ${
                selectedFlowId === flow.id
                  ? 'border-blue-600 shadow-md'
                  : 'border-gray-200 hover:border-gray-300'
              }`}
            >
              <h4 className="font-semibold text-gray-900">
                {flow.name}
              </h4>
            </button>
          ))}
        </div>

        {/* Confirm */}
        <button
          onClick={handleConfirm}
          disabled={!selectedFlowId}
          className="w-full h-12 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Confirm Selection
        </button>
      </div>
    </div>
  );
}