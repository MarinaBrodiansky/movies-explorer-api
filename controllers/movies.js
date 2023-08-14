const { ValidationError } = require('mongoose').Error;
const Movie = require('../models/movie');
const { BadRequestError } = require('../utils/errors/400-BadRequest');
const { ForbiddenError } = require('../utils/errors/403-Forbidden');
const { NotFoundError } = require('../utils/errors/404-NotFound');
const { STATUS_CREATED } = require('../utils/globalVars');

const createMovie = (req, res, next) => {
  const {
    country, director, duration, year, description, image, trailerLink,
    thumbnail, movieId, nameRU, nameEN,
  } = req.body;

  Movie.create({
    country,
    director,
    duration,
    year,
    description,
    image,
    trailerLink,
    thumbnail,
    movieId,
    nameRU,
    nameEN,
    owner: req.user._id,
  })
    .then((newMovie) => newMovie.populate('owner')
      .then((data) => res.status(STATUS_CREATED).send(data)))
    .catch((err) => {
      if (err instanceof ValidationError) {
        next(new BadRequestError('Переданы некорректные данные'));
      } else {
        next(err);
      }
    });
};

const getMovies = (req, res, next) => {
  const owner = req.user._id;
  Movie.find({ owner }).populate(['owner'])
    .then((movie) => res.send(movie))
    .catch((err) => next(err));
};

const deleteMovie = (req, res, next) => {
  const { movieId } = req.params;
  const { _id: userId } = req.user;

  Movie.findById(movieId)
    .orFail(new NotFoundError('Видео с таким id не найдено'))
    .then((movie) => {
      if (!movie.owner.equals(userId)) {
        return next(new ForbiddenError('Вы не можете удалить это видео'));
      }

      return Movie.deleteOne(movie)
        .then(() => {
          res.send({ message: 'Видео успешно удалено' });
        })
        .catch(next);
    })
    .catch(next);
};

module.exports = {
  createMovie,
  getMovies,
  deleteMovie,
};
