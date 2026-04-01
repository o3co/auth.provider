import { initLogger } from "@o3co/js.util.log";
import type { Logger } from "pino";

const logger: Logger = initLogger("provider", { level: process.env.LOG_LEVEL ?? "info" });
export default logger;
