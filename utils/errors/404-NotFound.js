const STATUS_NOT_FOUND = 404;

class NotFoundError extends Error {
  constructor(message = 'Not Found') {
    super(message);
    this.statusCode = STATUS_NOT_FOUND;
  }
}

module.exports = { NotFoundError, STATUS_NOT_FOUND };
