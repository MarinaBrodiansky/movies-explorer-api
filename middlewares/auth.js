const jwt = require('jsonwebtoken');
const { JWT_SECRET, COOKIE_KEY } = require('../config/settings');
const { UnauthorizedError } = require('../utils/errors/401-Unauthorized');

const authMiddleware = (req, _, next) => {
  const { authorization } = req.headers;
  let token = authorization ? authorization.replace('Bearer ', '') : null;

  if (!token) {
    if (req.cookies && COOKIE_KEY in req.cookies) {
      token = req.cookies[COOKIE_KEY];
    } else {
      return next(new UnauthorizedError('Необходима авторизация'));
    }
  }

  let payload;

  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return next(new UnauthorizedError('Необходима авторизация'));
  }

  req.user = payload; // записываем пейлоуд в объект запроса

  return next(); // пропускаем запрос дальше
};

module.exports = authMiddleware;
