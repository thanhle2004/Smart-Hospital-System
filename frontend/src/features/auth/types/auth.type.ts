// features/auth/types/auth.type.ts
import type { ChangeEvent, SyntheticEvent } from 'react'

// ─── Request / Response shapes ────────────────────────────────────────────────

export interface LoginRequest {
  email: string
  password: string
}

export interface LoginResponse {
  accessToken: string
  refreshToken: string
}

export interface RegisterRequest {
  email: string
  password: string
  role: string
}

export interface RegisterResponse {
  id: string
  email: string
}

export interface MeResponse {
  id: string           // field is 'id', not 'userId'
  email: string
  role?: string
  profile?: {
    fullName: string | null
    avatarUrl: string | null
  } | null
}

// ─── Login form ───────────────────────────────────────────────────────────────

export interface LoginFormValues {
  email: string
  password: string
}

export interface LoginFormErrors {
  email?: string
  password?: string
  general?: string
}

export interface UseLoginReturn {
  values: LoginFormValues
  errors: LoginFormErrors
  isLoading: boolean
  showPassword: boolean
  handleChange: (e: ChangeEvent<HTMLInputElement>) => void
  handleSubmit: (e: SyntheticEvent<HTMLFormElement>) => Promise<void>
  toggleShowPassword: () => void
}

// ─── Register form ────────────────────────────────────────────────────────────

export type UserRole = 'USER' | 'ADMIN' | 'DOCTOR'

export interface RegisterFormValues {
  email: string
  password: string
  confirmPassword: string
  role: string
}

export interface RegisterFormErrors {
  email?: string
  password?: string
  confirmPassword?: string
  role?: string
  general?: string
}

export interface UseRegisterReturn {
  values: RegisterFormValues
  errors: RegisterFormErrors
  isLoading: boolean
  showPassword: boolean
  showConfirmPassword: boolean
  handleChange: (
    e: ChangeEvent<HTMLInputElement | HTMLSelectElement>,
  ) => void
  handleSubmit: (e: SyntheticEvent<HTMLFormElement>) => Promise<void>
  toggleShowPassword: () => void
  toggleShowConfirmPassword: () => void
}