const STATUS_FORBIDDEN = 403;

class ForbiddenError extends Error {
  constructor(message = 'Forbidden') {
    super(message);
    this.statusCode = STATUS_FORBIDDEN;
  }
}

module.exports = { ForbiddenError, STATUS_FORBIDDEN };
