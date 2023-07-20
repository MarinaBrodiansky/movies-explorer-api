const STATUS_BAD_REQUEST = 400;

class BadRequestError extends Error {
  constructor(message = 'Bad Request') {
    super(message);
    this.statusCode = STATUS_BAD_REQUEST;
  }
}

module.exports = { BadRequestError, STATUS_BAD_REQUEST };
