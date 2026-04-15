'use client';

import {
  useState,
  type SyntheticEvent,
  type ChangeEvent,
} from 'react';
import { authService } from '../services/auth.service';
import type {
  LoginFormValues,
  LoginFormErrors,
  UseLoginReturn,
} from '../types/auth.type';

// ─── Validation ───────────────────────────────────────────────────────────────

function validate(values: LoginFormValues): LoginFormErrors {
  const errors: LoginFormErrors = {};

  if (!values.email.trim()) {
    errors.email = 'Email must not be empty';
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.email)) {
    errors.email = 'Email is invalid';
  }

  if (!values.password) {
    errors.password = 'Password must not be empty';
  } else if (values.password.length < 6) {
    errors.password = 'Password must be at least 6 characters long';
  }

  return errors;
}

function getLoginErrorMessage(err: unknown): string {
  if (!(err instanceof Error)) {
    return 'Login failed. Please try again.';
  }

  const message = err.message?.trim();
  if (!message) {
    return 'Login failed. Please try again.';
  }

  return message;
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useLogin(): UseLoginReturn {
  const [values, setValues] = useState<LoginFormValues>({
    email: '',
    password: '',
  });
  const [errors, setErrors] = useState<LoginFormErrors>({});
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const handleChange = (
    e: ChangeEvent<HTMLInputElement | HTMLSelectElement>
  ) => {
    const { name, value } = e.target;

    setValues((prev) => ({ ...prev, [name]: value }));

    if (errors[name as keyof LoginFormErrors]) {
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
      await authService.login(values);

      const me = await authService.me();
      const role = me.role;

      if (role === 'ADMIN') {
        window.location.href = '/admin/dashboard';
        return;
      }

      if (role === 'DOCTOR') {
        window.location.href = '/doctor/dashboard';
        return;
      }

      window.location.href = '/';

    } catch (err) {
      const message = getLoginErrorMessage(err);
      setErrors({ general: message });
    } finally {
      setIsLoading(false);
    }
  };

  const toggleShowPassword = () =>
    setShowPassword((prev) => !prev);

  return {
    values,
    errors,
    isLoading,
    showPassword,
    handleChange,
    handleSubmit,
    toggleShowPassword,
  };
}