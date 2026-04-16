'use client';

interface Props {
  name: string;
  email: string;
  phone: string;
  loading: boolean;
  error: string;
  onNameChange: (v: string) => void;
  onEmailChange: (v: string) => void;
  onYearOfBirthChange: (v: number) => void;
  onSubmit: () => void;
}

export default function ProfileSetupView({
  name,
  email,
  phone,
  yearOfBirth,
  loading,
  error,
  onNameChange,
  onEmailChange,
  onYearOfBirthChange,
  onSubmit,
}: Props) {
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
          <label className="text-sm font-medium mb-1">Year of Birth</label>
          <input
            value={yearOfBirth}
            onChange={(e) => onYearOfBirthChange(Number(e.target.value))}
            className="w-full h-12 px-3 border rounded-lg"
          />
        </div>

        {error && (
          <div className="text-red-600 text-sm">{error}</div>
        )}

        <button
          onClick={onSubmit}
          disabled={loading}
          className="w-full h-12 bg-blue-600 text-white rounded-lg"
        >
          {loading ? 'Creating...' : 'Create Profile'}
        </button>
      </div>
    </div>
  );
}