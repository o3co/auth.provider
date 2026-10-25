import { originEvidence } from "@mod/csrf";
import { grants, sessionIssuances } from "@mod/grants";
import { issuer } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { sessions } from "@mod/session";
import { tokens } from "@mod/tokens";
import { sessionGrant } from "./grant.ts";

const takes = [sessionIssuances, originEvidence, sessions, tokens, issuer];

export default defineModule({ name: "session-grant", takes }, (m) => [
	m.contribute(grants).by(async (c) => {
		if ((await c.collect(sessionIssuances)).length === 0) {
			return c.refuse(
				"session-grant",
				"its tokens must be recorded to their session, so that a logout ends them",
			);
		}
		return sessionGrant({
			evidence: await c.get(originEvidence),
			sessions: await c.get(sessions),
			tokens: await c.get(tokens),
			issuer: (await c.get(issuer)).url,
		});
	}),
]);
