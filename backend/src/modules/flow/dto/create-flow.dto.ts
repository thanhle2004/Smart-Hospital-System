import { z } from 'zod';

// This schema defines the structure of a room item in the flow, including the room type and its order in the flow.
export const flowRoomItemSchema = z.object({
  roomTypeId: z.number().int().positive(),
  defaultOrder: z.number().int().positive(),
});

// This schema defines dependencies between rooms in the flow, indicating that a certain room type must be completed before another can start.
export const flowRoomDependencyItemSchema = z.object({
  roomTypeId: z.number().int().positive(),
  requiredRoomTypeId: z.number().int().positive(),
});

// This schema defines the structure of the data required to create a new flow, including its name, the rooms involved, and any dependencies between those rooms.
export const createFlowSchema = z.object({
  name: z.string().min(1),
  rooms: z.array(flowRoomItemSchema).min(1),
  dependencies: z.array(flowRoomDependencyItemSchema).optional(),
});

export type FlowRoomItemDto = z.infer<typeof flowRoomItemSchema>;
export type FlowRoomDependencyItemDto = z.infer<typeof flowRoomDependencyItemSchema>;
export type CreateFlowDto = z.infer<typeof createFlowSchema>;