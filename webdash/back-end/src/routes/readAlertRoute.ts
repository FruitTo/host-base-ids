import { Express } from "express"
import readAlertControll from "../controllers/readAlertControll"
export default async function readAlertSer(app:Express):Promise<void> {
    app.get("/alert", readAlertControll)
}