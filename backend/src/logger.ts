import { createLogger, format, transports } from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import dotenv from 'dotenv-safe';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

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
