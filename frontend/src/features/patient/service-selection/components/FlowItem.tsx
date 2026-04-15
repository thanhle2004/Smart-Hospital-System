import { Flow } from '../types/flow.type'

interface Props {
  flow: Flow
  selected: boolean
  onSelect: (id: number) => void
}

export default function FlowItem({ flow, selected, onSelect }: Props) {
  return (
    <button
      onClick={() => onSelect(flow.id)}
      className={`w-full bg-white rounded-lg p-4 border-2 text-left transition ${
        selected
          ? 'border-blue-600 shadow-md'
          : 'border-gray-200 hover:border-gray-300'
      }`}
    >
      <h4 className="font-semibold text-gray-900">
        {flow.name}
      </h4>
    </button>
  )
}