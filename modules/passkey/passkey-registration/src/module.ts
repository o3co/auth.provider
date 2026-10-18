import { routes } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { sessions } from "@mod/session";
import { registrations } from "@mod/webauthn";
import { registrationRoutes } from "./routes.ts";
import { section } from "./section.ts";

export default defineModule({ name: "passkey-registration", section, replicaSafe: true }, (m) =>
	(["options", "verify"] as const).map((name) =>
		m.contribute(routes).by(
			async (c) =>
				registrationRoutes({
					sessions: await c.get(sessions),
					registrations: await c.get(registrations),
					window: { limit: c.section.requests, ms: c.section.window * 1000 },
				})[name],
		),
	),
);
