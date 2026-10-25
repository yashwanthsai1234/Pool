// One error type for every refusal the API makes: an HTTP status, a stable code and a message. Handlers throw it;
// the Fastify error handler turns it into `{ error, message, issues? }`.
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly issues?: readonly { path: string; message: string }[];
  constructor(status: number, code: string, message: string, issues?: readonly { path: string; message: string }[]) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    if (issues) this.issues = issues;
  }
}

export const badRequest = (message: string, issues?: readonly { path: string; message: string }[]) =>
  new ApiError(400, 'invalid_request', message, issues);
export const unauthorized = (code: string, message: string) => new ApiError(401, code, message);
export const forbidden = (code: string, message: string) => new ApiError(403, code, message);
export const notFound = (message: string) => new ApiError(404, 'not_found', message);
export const conflict = (code: string, message: string) => new ApiError(409, code, message);
export const unprocessable = (code: string, message: string) => new ApiError(422, code, message);
