const STATUS_CONFLICT = 409;

class ConflictRequestError extends Error {
  constructor(message = 'ConflictRequest') {
    super(message);
    this.statusCode = STATUS_CONFLICT;
  }
}

module.exports = { ConflictRequestError, STATUS_CONFLICT };
