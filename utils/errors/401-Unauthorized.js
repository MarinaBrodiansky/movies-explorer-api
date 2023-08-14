const STATUS_UNAUTHORIZED = 401;

class UnauthorizedError extends Error {
  constructor(message = 'Unauthorized') {
    super(message);
    this.statusCode = STATUS_UNAUTHORIZED;
  }
}

module.exports = { UnauthorizedError, STATUS_UNAUTHORIZED };
