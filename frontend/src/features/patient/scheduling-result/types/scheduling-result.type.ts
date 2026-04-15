export interface Room {
  id: number
  name: string
  roomNumber: number
  roomTypeId: number
}

export interface VisitRoom {
  id: number
  status: 'WAITING' | 'IN_PROGRESS' | 'COMPLETED' | 'SKIPPED'
  room: Room | null
  roomTypeId: number | null
}

export interface VisitFlow {
  id: number
  roomTypeId: number
  orderIndex: number
  roomType: {
    name: string
  }
}

export interface Visit {
  id: string
  visitFlows: VisitFlow[]
  visitRooms: VisitRoom[]
  patientId: string
}