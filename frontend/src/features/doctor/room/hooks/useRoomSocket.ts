// features/doctor/room/hooks/useRoomSocket.ts
'use client'

import { useEffect, useRef } from 'react'
import { io, type Socket } from 'socket.io-client'
import type {
  SocketDoctorsUpdatedPayload,
  SocketQueueUpdatedPayload,
} from '../types/room.type'

const SOCKET_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:5000'

interface UseRoomSocketOptions {
  roomId: number
  onQueueUpdated?: (payload: SocketQueueUpdatedPayload) => void
  onDoctorsUpdated?: (payload: SocketDoctorsUpdatedPayload) => void
}

export function useRoomSocket({
  roomId,
  onQueueUpdated,
  onDoctorsUpdated,
}: UseRoomSocketOptions) {
  // Use refs so callbacks always read latest values and avoid stale closures
  const onQueueRef = useRef(onQueueUpdated)
  const onDoctorsRef = useRef(onDoctorsUpdated)

  useEffect(() => {
    onQueueRef.current = onQueueUpdated
    onDoctorsRef.current = onDoctorsUpdated
  })

  useEffect(() => {
    const socket: Socket = io(SOCKET_URL, {
      withCredentials: true, // send cookie for auth
      transports: ['websocket'],
    })

    socket.on('connect', () => {
      socket.emit('join-room', { roomId })
    })

    socket.on(
      `room:${roomId}:queue-updated`,
      (payload: SocketQueueUpdatedPayload) => {
        onQueueRef.current?.(payload)
      },
    )

    socket.on(
      `room:${roomId}:doctors-updated`,
      (payload: SocketDoctorsUpdatedPayload) => {
        onDoctorsRef.current?.(payload)
      },
    )

    return () => {
      socket.emit('leave-room', { roomId })
      socket.disconnect()
    }
  }, [roomId])
}