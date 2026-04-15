// Keep this page as a Server Component (no 'use client')
import { RegisterForm } from '@/features/auth/components/RegisterForm';

interface RegisterPageProps {
  searchParams: Promise<{ redirect?: string }>;
}

export default async function RegisterPage({ searchParams }: RegisterPageProps) {
  const params = await searchParams;
  const redirectTo = params?.redirect ?? '/login';

  return <RegisterForm redirectTo={redirectTo} />;
}