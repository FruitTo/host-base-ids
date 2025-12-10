import { time } from "console";
import { readAlertRepo } from "../repository/readAlert";

export async function readAlertService(date:string){
  const timestamp = date;
  const result = await readAlertRepo(timestamp);
  return result;
}