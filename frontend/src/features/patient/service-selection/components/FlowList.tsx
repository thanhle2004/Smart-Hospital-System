import { Flow } from '../types/flow.type'
import FlowItem from './FlowItem'

interface Props {
  flows: Flow[]
  selectedFlowId: number | null
  onSelect: (id: number) => void
}

export default function FlowList({ flows, selectedFlowId, onSelect }: Props) {
  return (
    <div className="space-y-3">
      {flows.map(flow => (
        <FlowItem
          key={flow.id}
          flow={flow}
          selected={selectedFlowId === flow.id}
          onSelect={onSelect}
        />
      ))}
    </div>
  )
}