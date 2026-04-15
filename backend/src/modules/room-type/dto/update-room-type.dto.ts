import { z } from 'zod';
import { createRoomTypeSchema } from './create-room-type.dto';

export const updateRoomTypeSchema = createRoomTypeSchema.partial();

export type UpdateRoomTypeDto = z.infer<typeof updateRoomTypeSchema>;