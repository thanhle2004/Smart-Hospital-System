'use client';

import {
  useState,
  type SyntheticEvent,
  type ChangeEvent,
} from 'react';
import { useRouter } from 'next/navigation';
import { authService } from '../services/auth.service';
import type {
  RegisterFormValues,
  RegisterFormErrors,
  UseRegisterReturn,
} from '../types/auth.type';

// ─── Validation ───────────────────────────────────────────────────────────────

function validate(values: RegisterFormValues): RegisterFormErrors {
  const errors: RegisterFormErrors = {};

  if (!values.email.trim()) {
    errors.email = 'Email cannot be empty';
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.email)) {
    errors.email = 'Invalid email format';
  }

  if (!values.password) {
    errors.password = 'Password cannot be empty';
  } else if (values.password.length < 6) {
    errors.password = 'Password must be at least 6 characters';
  }

  if (!values.confirmPassword) {
    errors.confirmPassword = 'Please confirm your password';
  } else if (values.password !== values.confirmPassword) {
    errors.confirmPassword = 'Passwords do not match';
  }

  if (!values.role) {
    errors.role = 'Please select a role';
  }

  return errors;
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useRegister(
  redirectTo = '/login'
): UseRegisterReturn {
  const router = useRouter();

  const [values, setValues] = useState<RegisterFormValues>({
    email: '',
    password: '',
    confirmPassword: '',
    role: '',
  });

  const [errors, setErrors] = useState<RegisterFormErrors>({});
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] =
    useState(false);

  const handleChange = (
    e: ChangeEvent<HTMLInputElement | HTMLSelectElement>
  ) => {
    const { name, value } = e.target;

    setValues((prev) => ({ ...prev, [name]: value }));

    if (errors[name as keyof RegisterFormErrors]) {
      setErrors((prev) => ({ ...prev, [name]: undefined }));
    }
  };

  const handleSubmit = async (
    e: SyntheticEvent<HTMLFormElement>
  ) => {
    e.preventDefault();

    const validationErrors = validate(values);
    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      return;
    }

    setIsLoading(true);
    setErrors({});

    try {
      await authService.register({
        email: values.email,
        password: values.password,
        role: values.role,
      });

      router.push(redirectTo);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : 'Failed to register';

      setErrors({ general: message });
    } finally {
      setIsLoading(false);
    }
  };

  return {
    values,
    errors,
    isLoading,
    showPassword,
    showConfirmPassword,
    handleChange,
    handleSubmit,
    toggleShowPassword: () => setShowPassword((v) => !v),
    toggleShowConfirmPassword: () =>
      setShowConfirmPassword((v) => !v),
  };
}