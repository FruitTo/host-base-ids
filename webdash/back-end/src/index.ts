import express,{ Express } from "express";
import cors from "cors";
import readAlertRoute from "./routes/readAlertRoute";
import "dotenv/config"

const app:Express = express();
app.
    use(cors()).
    use(express.urlencoded()).
    use(express.json())

readAlertRoute(app);

app.listen(process.env.SERVER_PORT, () => {
    console.log("Server port 3000 is online.")
})