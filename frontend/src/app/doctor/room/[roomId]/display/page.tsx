'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import { doctorRoomService } from '@/features/doctor/room/services/room.service'
import { DisplayQueue } from '@/features/doctor/room/components/DisplayQueue'

export default function DisplayPage() {
  const params = useParams()
  const roomId = Number(params.roomId)
  const [roomName, setRoomName] = useState<string>('')

  useEffect(() => {
    doctorRoomService
      .getOne(roomId)
      .then((r) => setRoomName(r.name))
      .catch(() => setRoomName(`Room ${roomId}`))
  }, [roomId])

  return <DisplayQueue roomId={roomId} roomName={roomName} />
}