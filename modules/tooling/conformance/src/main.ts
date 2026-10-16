/** What the area modules build their scenes and set-ups on; the new system is registered as a target. */
import "./drivers/composed.ts";

export {
	type Area,
	type AreaDriver,
	type AreaScene,
	area,
	areaTarget,
	type NewPart,
	onNew,
	type Party,
	type PatternPart,
	registerDriver,
	sceneOf,
} from "./areas.ts";
export { type AuditTrail, auditEvents, type SentEvent } from "./audit/audit.ts";
export { baseEnv, freePort, type Launch, launch, type Started, startRedis } from "./driver.ts";
export { type Fake, fakeHttp, type Received, type Scripted } from "./fake.ts";
export { faultyTarget } from "./faults.ts";
export type { Mailbox, Mailed } from "./smtp.ts";
