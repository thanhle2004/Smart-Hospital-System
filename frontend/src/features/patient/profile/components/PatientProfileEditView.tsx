'use client';

interface Props {
  loading: boolean;
  submitting: boolean;
  error: string;
  name: string;
  email: string;
  phone: string;
  yearOfBirth: number;
  onNameChange: (v: string) => void;
  onEmailChange: (v: string) => void;
  onYearOfBirthChange: (v: number) => void;
  onSubmit: () => void;
  onBack: () => void;
}

export default function PatientProfileEditView({
  loading,
  submitting,
  error,
  name,
  email,
  phone,
  yearOfBirth,
  onNameChange,
  onEmailChange,
  onYearOfBirthChange,
  onSubmit,
  onBack,
}: Props) {
  if (loading) {
    return (
      <div className="p-10 text-center text-lg font-semibold">Loading profile...</div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 px-6 py-10">
      <div className="max-w-xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-blue-900">Edit Profile</h1>
            <p className="text-gray-600">Update your patient information</p>
          </div>
          <button
            onClick={onBack}
            className="px-4 h-10 rounded-lg border bg-white"
          >
            Back
          </button>
        </div>

        <div className="bg-white rounded-lg p-6 shadow border space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Full Name *</label>
            <input
              value={name}
              onChange={(e) => onNameChange(e.target.value)}
              className="w-full h-12 px-3 border rounded-lg"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Email</label>
            <input
              value={email}
              onChange={(e) => onEmailChange(e.target.value)}
              className="w-full h-12 px-3 border rounded-lg"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Phone</label>
            <input
              value={phone}
              disabled
              className="w-full h-12 px-3 border rounded-lg bg-gray-100"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Year of Birth</label>
            <input
              type="number"
              value={yearOfBirth}
              onChange={(e) => onYearOfBirthChange(Number(e.target.value))}
              className="w-full h-12 px-3 border rounded-lg"
            />
          </div>

          {error && <p className="text-sm text-red-600">{error}</p>}

          <button
            onClick={onSubmit}
            disabled={submitting}
            className="w-full h-12 bg-blue-600 text-white rounded-lg disabled:opacity-60"
          >
            {submitting ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </div>
    </div>
  );
}
