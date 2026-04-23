import mysql from "mysql2/promise";
import { env } from "./env.js";

export const pool = mysql.createPool({
  host: env.MYSQL_HOST,
  port: env.MYSQL_PORT,
  user: env.MYSQL_USER,
  password: env.MYSQL_PASSWORD,
  database: env.MYSQL_DATABASE,
  dateStrings: true,
  waitForConnections: true,
  connectionLimit: 8,
  maxIdle: 8,
  idleTimeout: 60_000,
  queueLimit: 0,
  enableKeepAlive: true
});

export async function queryOne<T>(sql: string, params: any[] = []): Promise<T | null> {
  const [rows] = await pool.execute(sql, params);
  const typedRows = rows as T[];
  return typedRows[0] ?? null;
}

export async function queryMany<T>(sql: string, params: any[] = []): Promise<T[]> {
  const [rows] = await pool.execute(sql, params);
  return rows as T[];
}
