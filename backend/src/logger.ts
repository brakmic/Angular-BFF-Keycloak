/**
 * logger.ts
 * 
 * Description:
 *  - Provides application-wide logging using Winston.
 *  - Supports console and optional file-based rotation logs.
 *  - Reads LOG_LEVEL, LOG_TO_FILE, and LOG_DIRECTORY from environment variables.
 * 
 * API:
 *  - Exported Members:
 *      logger: Winston Logger instance for logging throughout the app.
 *      stream: Stream adapter for Morgan (HTTP request logging).
 * 
 * @module logger
 */
import { createLogger, format, Logger, transports } from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import dotenv from 'dotenv-safe';
import TransportStream from 'winston-transport';
import { getFilePath } from './utils/paths';
import path from 'path';

const { __dirname } = getFilePath(import.meta.url);

// Load environment variables
dotenv.config({
  path: path.join(__dirname, '../.env'),
  example: path.join(__dirname, '../.env.example'),
  allowEmptyValues: true,
});

// Extract logging configuration from environment variables
const {
  LOG_LEVEL = 'info',
  LOG_TO_FILE = 'false',
  LOG_DIRECTORY = 'logs',
} = process.env;

// Define log formats
const logFormat = format.combine(
  format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  format.printf(({ timestamp, level, message, ...meta }) => {
    const metaString = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
    return `${timestamp} [${level.toUpperCase()}]: ${message} ${metaString}`;
  })
);

// Initialize logger transports
const loggerTransports: TransportStream[] = [
  new transports.Console({
    level: LOG_LEVEL,
    format: format.combine(
      format.colorize(),
      format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      format.printf(({ timestamp, level, message, ...meta }) => {
        const metaString = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
        return `${timestamp} [${level}]: ${message} ${metaString}`;
      })
    ),
    handleExceptions: true,
  }),
];

// Conditionally add DailyRotateFile transport
if (LOG_TO_FILE.toLowerCase() === 'true') {
  loggerTransports.push(
    new DailyRotateFile({
      level: LOG_LEVEL,
      filename: path.join(LOG_DIRECTORY, '%DATE%-results.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '14d',
      format: logFormat,
      handleExceptions: true,
    })
  );
}

// Create the logger
const logger: Logger = createLogger({
  level: LOG_LEVEL,
  transports: loggerTransports,
  exitOnError: false, // Do not exit on handled exceptions
});

// Define stream for morgan integration
const stream = {
  write: (message: string) => {
    // Remove newline characters to prevent double-spacing in logs
    logger.info(message.trim());
  },
};

export { logger, stream };
