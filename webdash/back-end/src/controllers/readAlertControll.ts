import { Request, Response } from "express";
import { readAlertService } from "../services/readAlert";
export default async function readAlertControll(req:Request, res:Response){
    try{
        const date = req.query.date;
        const arr = await readAlertService(date as string);
        res.json(arr);
    }catch {
        res.json([]);
    }
}