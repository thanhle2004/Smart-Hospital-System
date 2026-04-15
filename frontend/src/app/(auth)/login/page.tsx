import type { Metadata } from 'next';
import { LoginForm } from '@/features/auth/components/LoginForm';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';

export const metadata: Metadata = {
  title: 'Login',
  description: 'Login to your account to access the Smart Hospital System dashboard and manage your appointments, patients, and more.',
};

export default async function LoginPage() {
  const cookieStore = await cookies();
  const token = cookieStore.get('access_token')?.value;

  if (token) {
    redirect('/');
  }

  return <LoginForm />;
}