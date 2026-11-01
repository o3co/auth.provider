import { audit } from "@mod/audit";
import { routes } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { registrations } from "@mod/passkeys";
import { sessions } from "@mod/session";
import { subjectRevocation } from "@mod/subject-revocation";
import { exchangeOver } from "./exchange/exchange.ts";
import { managingRoutes } from "./managing/managing.ts";
import { registeringRoutes } from "./registering/registering.ts";
import { section } from "./section.ts";

export default defineModule(
	{
		name: "passkey-registration",
		section,
		replicaSafe: true,
		takes: [audit, registrations, sessions, subjectRevocation],
	},
	(m) =>
		(["options", "verify", "list", "rename", "remove"] as const).map((name) =>
			m.contribute(routes).by(async (c) => {
				const exchange = exchangeOver(await c.get(sessions), {
					limit: c.section.requests,
					ms: c.section.window * 1000,
				});
				const parts = {
					exchange,
					registrations: await c.get(registrations),
					audit: await c.get(audit),
				};
				return {
					...registeringRoutes({ ...parts, revocation: await c.get(subjectRevocation) }),
					...managingRoutes(parts),
				}[name];
			}),
		),
);
