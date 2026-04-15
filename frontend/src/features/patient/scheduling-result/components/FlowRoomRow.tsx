import { VisitFlow, VisitRoom } from '../types/scheduling-result.type'

interface Props {
  fr: VisitFlow
  vr?: VisitRoom
}

export default function FlowRoomRow({ fr, vr }: Props) {

  let status = 'PENDING'

  if (vr?.status === 'COMPLETED') status = 'COMPLETED'
  if (vr?.status === 'WAITING') status = 'CURRENT'
  if (vr?.status === 'IN_PROGRESS') status = 'IN_PROGRESS'

  return (
    <div className="bg-white p-4 rounded-lg border flex justify-between items-center">
      <div>
        <div className="font-medium">
          {fr.roomType.name}
        </div>

        {vr?.room && (
          <div className="text-xs text-gray-500">
            Room {vr.room.roomNumber}
          </div>
        )}
      </div>

      <span className="text-sm font-semibold">
        {status === 'COMPLETED' && '✅ COMPLETED'}
        {status === 'CURRENT' && '🟡 CURRENT'}
        {status === 'IN_PROGRESS' && '🔵 IN PROGRESS'}
        {status === 'PENDING' && '⚪ PENDING'}
      </span>
    </div>
  )
}