import { ApiError } from '../typings';

export class JacksonError extends Error {
  public name: string;
  public statusCode: number;
  public internalError?: string;

  constructor(message: string, statusCode = 500, internalError: string = '') {
    super(message);

    this.name = this.constructor.name;
    this.statusCode = statusCode;
    if (internalError) {
      this.internalError = internalError;
    }

    Error.captureStackTrace(this, this.constructor);
  }
}

export const apiError = (err: any) => {
  const { message, statusCode = 500 } = err;

  return { data: null, error: { message, code: statusCode } as ApiError };
};
