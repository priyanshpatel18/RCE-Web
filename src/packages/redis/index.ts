import "dotenv/config";
import Redis from "ioredis";

const REDIS_HOST = process.env.REDIS_HOST;
const REDIS_PORT = Number(process.env.REDIS_PORT);
const REDIS_PASSWORD = process.env.REDIS_PASSWORD;

export const redisClient = new Redis({
  host: REDIS_HOST,
  port: REDIS_PORT!,
  password: REDIS_PASSWORD,
});
