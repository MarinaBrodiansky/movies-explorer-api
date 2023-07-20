const { errors } = require('celebrate');
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const {
  PORT,
  ORIGINS,
  MONGO_DB,
  LIMITER,
} = require('./config/settings');
const errorHandler = require('./middlewares/errorHandler');
const { requestLogger, errorLogger } = require('./middlewares/logger');
const router = require('./routes');

mongoose.set('strictQuery', false);
mongoose.connect(MONGO_DB);

const app = express();

app.use(cors({ origin: ORIGINS }));
app.use(express.json());
app.use(requestLogger);
app.use(LIMITER); // AntiDOS for all requests
app.use(helmet());

app.use(errorLogger);
app.use(router);
app.use(errors());
app.use(errorHandler);

app.listen(PORT, () => console.log('Server started on port:', PORT));
