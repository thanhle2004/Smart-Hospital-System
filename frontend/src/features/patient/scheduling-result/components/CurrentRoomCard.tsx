import { VisitRoom } from '../types/scheduling-result.type'

interface Props {
  room: VisitRoom
}

export default function CurrentRoomCard({ room }: Props) {
  if (!room.room) return null

  return (
    <div className="bg-blue-100 p-4 rounded-lg">
      <p className="text-sm text-gray-600">
        CURRENT ROOM
      </p>

      <h2 className="text-lg font-bold text-blue-800">
        {room.room.name} - Room {room.room.roomNumber}
      </h2>
    </div>
  )
}