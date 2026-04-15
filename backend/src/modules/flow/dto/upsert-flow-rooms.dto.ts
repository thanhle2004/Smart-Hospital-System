import { z } from 'zod';
import {
  flowRoomDependencyItemSchema,
  flowRoomItemSchema,
} from './create-flow.dto';

// This schema defines the structure of the data required to update the rooms and their dependencies in an existing flow. 
// It includes an array of room items and an optional array of dependencies between those rooms.
export const upsertFlowRoomsSchema = z.object({
  rooms: z.array(flowRoomItemSchema).min(1),
  dependencies: z.array(flowRoomDependencyItemSchema).optional(),
});

export type UpsertFlowRoomsDto = z.infer<typeof upsertFlowRoomsSchema>;