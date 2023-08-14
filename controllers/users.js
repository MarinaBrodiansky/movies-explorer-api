// const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { ValidationError } = require('mongoose').Error;
const { JWT_SECRET, COOKIE_KEY } = require('../config/settings');
const { BadRequestError } = require('../utils/errors/400-BadRequest');
const { NotFoundError } = require('../utils/errors/404-NotFound');
const { ConflictRequestError } = require('../utils/errors/409-ConflictRequest');

const User = require('../models/user');

const createUser = (req, res, next) => {
  const {
    name, email, password,
  } = req.body;

  bcrypt
    .hash(password, 10)
    .then((hashedPassword) => {
      User.create({
        name,
        email,
        password: hashedPassword,
      })
        .then((user) => {
          res.status(201).send({
            name: user.name,
            email: user.email,
          });
        })
        .catch((err) => {
          if (err instanceof ValidationError) {
            next(new BadRequestError('Некорректные данные'));
          } else if (err.code === 11000) {
            next(new ConflictRequestError('Такой пользователь уже существует'));
          } else {
            next(err);
          }
        });
    })
    .catch(next);
};

const getCurrentUser = (req, res, next) => {
  User.findById(req.user._id)
    .orFail(new NotFoundError('Пользователь с таким ID не найден'))
    .then((foundUser) => res.send(foundUser))
    .catch(next);
};

const updateUser = (req, res, next) => {
  const { name, email } = req.body;

  User.findByIdAndUpdate(req.user._id, { name, email }, { new: true, runValidators: true })
    .then((updateduser) => res.send(updateduser))
    .catch((err) => {
      if (err.name === 'ValidationError') {
        next(new BadRequestError('Переданы некорректные данные'));
      } else if (err.code === 11000) {
        next(new ConflictRequestError('Такой пользователь уже существует'));
      }
      next(err);
    });
};

const login = (req, res, next) => {
  const { email, password } = req.body;
  return User.findUserByCredentials(email, password)
    .then((user) => {
      const token = jwt.sign({ _id: user._id }, JWT_SECRET, { expiresIn: '7d' });
      res.cookie(COOKIE_KEY, token, {
        maxAge: 86400000 * 7,
        httpOnly: true, // only backend
        secure: true,
      });
      return res.send({ email, token });
    })
    .catch(next);
};

const signOut = (req, res) => {
  res.clearCookie(COOKIE_KEY);

  return res.send({ message: 'Давай, до свидания!' });
};

module.exports = {
  createUser,
  getCurrentUser,
  updateUser,
  signOut,
  login,
};
