class AppError extends Error {
  constructor(message, statusCode) {
    super(message);

    this.statusCode = statusCode;
    this.status = String(statusCode).startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    // NOTE Creates a .stack property on targetObject, which when accessed returns a string representing the location in the code at which Error.captureStackTrace() was called.
    // NOTE The optional constructorOpt argument accepts a function. If given, all frames above constructorOpt, including constructorOpt, will be omitted from the generated stack trace.
    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = AppError;
