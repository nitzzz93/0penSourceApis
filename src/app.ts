import express from 'express';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import validateEnv from './utils/validateEnv';
import morgan from 'morgan';
dotenv.config();
validateEnv();

export const corsOptions = {
    origin: [
      'https://studio.apollographql.com',
      'http://localhost:8000',
      'http://localhost:3000',
    ],
    credentials: true,
  };
const app = express();

// MIDDLEWARE
app.use(cookieParser());

// LOGGER
app.use(morgan('dev'));

process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION 🔥 Shutting down...');
  console.error('Error🔥', err.message);
  process.exit(1);
});

export default app;
