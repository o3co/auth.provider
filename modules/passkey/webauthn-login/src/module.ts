import { audit } from "@mod/audit";
import { grants } from "@mod/grants";
import { routes } from "@mod/http";
import { issuer } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { lineage } from "@mod/refresh";
import { subjectRevocation } from "@mod/subject-revocation";
import { passkeys } from "@mod/webauthn";
import { passkeyGrant } from "./grant.ts";
import { optionsRoute } from "./options.ts";
import { section } from "./section.ts";

export default defineModule({ name: "webauthn-login", section, replicaSafe: true }, (m) => [
	m.contribute(grants).by(async (c) =>
		passkeyGrant({
			passkeys: await c.get(passkeys),
			lineage: await c.get(lineage),
			revocation: await c.get(subjectRevocation),
			audit: await c.get(audit),
			issuer: (await c.get(issuer)).url,
		}),
	),
	m.contribute(routes).by(async (c) =>
		optionsRoute(await c.get(passkeys), {
			limit: c.section.requests,
			ms: c.section["window-seconds"] * 1000,
		}),
	),
]);
