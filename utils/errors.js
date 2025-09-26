export class AppError extends Error {
  constructor(message, statusCode = 500, errorCode = 'GENERIC_ERROR') {
    super(message);
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.isOperational = true; // Mark as operational error
    Error.captureStackTrace(this, this.constructor);
  }
}

export class BadRequestError extends AppError {
  constructor(message = 'Bad Request', errorCode = 'BAD_REQUEST') {
    super(message, 400, errorCode);
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'Unauthorized', errorCode = 'UNAUTHORIZED') {
    super(message, 401, errorCode);
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Forbidden', errorCode = 'FORBIDDEN') {
    super(message, 403, errorCode);
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'Not Found', errorCode = 'NOT_FOUND') {
    super(message, 404, errorCode);
  }
}

export class TooManyRequestsError extends AppError {
  constructor(message = 'Too Many Requests', errorCode = 'TOO_MANY_REQUESTS') {
    super(message, 429, errorCode);
  }
}
