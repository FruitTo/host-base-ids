import { Client } from "pg";
export async function dbConnect() {
  try {
    const client: Client = new Client({
      user: process.env.PG_USER,
      database: process.env.PG_DB,
      port: Number(process.env.PG_PORT),
      password: process.env.PG_PASSWORD,
      host: process.env.PG_HOST,
      // ssl: { rejectUnauthorized: false },
      // ssl: true,
    });
    await client.connect();
    return client;
  } catch (error) {
    console.log(error);
    throw "error";
  }
}
