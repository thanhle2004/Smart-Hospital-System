// features/doctor/dashboard/types/dashboard.type.ts

export interface DoctorStats {
  totalToday: number
  waiting: number
  inProgress: number
  completed: number
}

export interface RoomDoctor {
  id: number
  roomId: number
  doctorId: string
  startTime: string
  endTime: string | null
  isActive: boolean
  doctor: {
    id: string
    email: string
    profile: {
      fullName: string | null
      avatarUrl: string | null
    } | null
  }
}

export interface RoomType {
  id: number
  name: string
  description: string | null
  avgProcessTime: number
  defaultCapacity: number
}

export interface RoomDetail {
  id: number
  name: string
  roomNumber: number
  capacity: number
  roomTypeId: number | null
  roomType: RoomType | null
  avgProcessTime: number
  isActive: boolean
  roomAssignments: RoomDoctor[]
}

export interface PatientType {
  id: number
  code: string
  name: string
  basePriority: number | null
}

export interface Patient {
  id: string
  name: string
  email: string | null
  phone: string
  yearOfBirth: number
  patientTypeId: number
  patientType: PatientType
}

export interface Visit {
  id: string
  patientId: string
  flowId: number
  flow?: {
    id: number
    name: string
  } | null
  checkInTime: string
  status: 'WAITING' | 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED'
  patient: Patient
}

export interface VisitRoom {
  id: number
  visitId: string
  roomId: number | null
  roomTypeId: number | null
  priority: number | null
  status: 'WAITING' | 'IN_PROGRESS' | 'COMPLETED' | 'SKIPPED'
  createdAt: string
  startTime: string | null
  endTime: string | null
  visit: Visit
  roomType?: RoomType
}

export interface ActiveRoom {
  room: RoomDetail
  currentPatient: VisitRoom | null
  waitingCount: number
}

export interface VisitFlowDependency {
  visitFlowId: number
  requiredVisitFlowId: number
}

export interface VisitFlow {
  id: number
  visitId: string
  roomTypeId: number
  orderIndex: number
  isSkipped: boolean
  isCompleted?: boolean
  isInProgress?: boolean
  isAddedManually: boolean
  roomType: RoomType
  dependencies: VisitFlowDependency[]
  requiredBy: VisitFlowDependency[]
}

// WebSocket payloads
export interface SocketQueueUpdatedPayload {
  roomId: number
  waiting: VisitRoom[]
  current: VisitRoom | null
}

export interface SocketDoctorsUpdatedPayload {
  roomId: number
  doctors: RoomDoctor[]
  capacity: number
}