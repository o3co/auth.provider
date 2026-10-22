import { audit } from "@mod/audit";
import { routes } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { registrations } from "@mod/passkeys";
import { sessions } from "@mod/session";
import { subjectRevocation } from "@mod/subject-revocation";
import { registrationRoutes } from "./routes.ts";
import { section } from "./section.ts";

export default defineModule({ name: "passkey-registration", section, replicaSafe: true }, (m) =>
	(["options", "verify", "list", "rename", "remove"] as const).map((name) =>
		m.contribute(routes).by(
			async (c) =>
				registrationRoutes({
					sessions: await c.get(sessions),
					registrations: await c.get(registrations),
					revocation: await c.get(subjectRevocation),
					audit: await c.get(audit),
					window: { limit: c.section.requests, ms: c.section.window * 1000 },
				})[name],
		),
	),
);
