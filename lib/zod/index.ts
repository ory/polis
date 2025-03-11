import { ApiError } from '@lib/error';
import z, { ZodType } from 'zod';

export * from './schema';

export const validateWithSchema = <ZSchema extends ZodType>(schema: ZSchema, data: any) => {
  const result = schema.safeParse(data);

  if (!result.success) {
    throw new ApiError(`Validation Error: ${result.error.errors.map((e) => e.message)[0]}`, 422);
  }

  return result.data as z.infer<ZSchema>;
};
