import { z } from 'zod';

export const getSsoConnectionsSchema = z.object({
  sort: z.optional(z.literal('true')),
});
