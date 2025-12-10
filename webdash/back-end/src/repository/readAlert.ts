import { dbConnect } from "../config/dbConnect";

export async function readAlertRepo(date: string) {
  try {
    const client = await dbConnect();
    const sql = `
      SELECT "timestamp", src_ip, src_port, dst_ip, dst_port, protocol, attack_type, prob
      FROM alert
      WHERE left("timestamp", 10) = to_char(to_date($1,'DD-MM-YYYY'),'YYYY-MM-DD')
      ORDER BY "timestamp" DESC
    `;
    const result = await client.query(sql, [date]);
    client.end();
    return result.rows;
  }catch (err){
    console.error(err);
  }
}
