const router = require('express').Router();
const { createUser, login } = require('../controllers/users');
const auth = require('../middlewares/auth');
const { NotFoundError } = require('../utils/errors/404-NotFound');
const { validateCreateUser, validateLogin } = require('../middlewares/validation');

router.use('/users', auth, require('./users'));
router.use('/movies', auth, require('./movies'));

router.use('/signup', validateCreateUser, createUser);
router.use('/signin', validateLogin, login);

router.use('*', auth, () => {
  throw new NotFoundError('Не найдено');
});
module.exports = router;
