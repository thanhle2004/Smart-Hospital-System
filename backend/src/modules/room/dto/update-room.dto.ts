import { z } from 'zod';
import { baseRoomSchema } from './create-room.dto';

export const updateRoomSchema = baseRoomSchema.partial().superRefine((data, ctx) => {
	if (data.roomTypeId != null && (data.avgProcessTime == null || data.avgProcessTime <= 0)) {
		ctx.addIssue({
			code: z.ZodIssueCode.custom,
			path: ['avgProcessTime'],
			message:
				'Average processing time is required and must be greater than 0 when room type is selected',
		});
	}
});

export type UpdateRoomDto = z.infer<typeof updateRoomSchema>;