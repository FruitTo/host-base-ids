import { readFile } from "node:fs/promises";
import { format, parse } from "date-fns";
import * as path from "node:path";

export default async function readAlertSer(date: string): Promise<any> {
  try {
    const inp = date;
    // const inp = "15-09-2025";

    // Parser
    const parsed = parse(inp, "dd-MM-yyyy", new Date());
    const day = format(parsed, "dd");
    const month = format(parsed, "MM");
    const year = format(parsed, "yyyy");

    // Find Path
    const baseDir = path.resolve("../../alert");
    const filePath =
      baseDir + "/" + year + "/" + month + "/" + day + "/" + inp + ".jsonl";
    console.log(baseDir);

    const text = await readFile(filePath, "utf8");
    const arr = text
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((e) => JSON.parse(e));

    console.log(arr.length);
    return arr;
  } catch (error) {
    console.log(error);
  }
}
