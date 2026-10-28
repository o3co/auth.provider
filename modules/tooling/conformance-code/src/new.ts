import { onNew } from "@mod/conformance";
import { identityArea } from "@mod/conformance-identity";
import { secondFactorArea, stepUpPage } from "@mod/conformance-second-factor";
import { codeArea } from "./area.ts";

onNew(codeArea, (part, scene) => {
	const origin = new URL(identityArea.in(scene)?.origin ?? "http://127.0.0.1").origin;
	return {
		modules: [
			"@mod/consent",
			"@mod/code-grant",
			"@mod/acr",
			"@mod/authorize",
			"@mod/oidc",
			...(part.refresh ? ["@mod/refresh"] : []),
			...(part.sessionGrant ? ["@mod/session-grant"] : []),
			...(part.documents ? ["@mod/outbound", "@mod/clients-cimd"] : []),
			...(part.logout ? ["@mod/rp-logout"] : []),
			...(part.userinfo ? ["@mod/userinfo"] : []),
		],
		store: "volatile",
		...(part.without ? { without: part.without } : {}),
		config: {
			// The claims parameter is taken, as a deployment that runs 0.19 on every host takes it.
			"claims-selection": { mode: "on" },
			// A code that comes again must revoke what it gave.
			tokens: { revocation: "denylist" },
			authorize: {
				"login-page": `${origin}/login`,
				...(part.acr && secondFactorArea.in(scene)
					? { "step-up-page": `${origin}${stepUpPage}` }
					: {}),
			},
			// Without its page, consent cannot ask.
			...(part.withoutConsent ? {} : { consent: { page: `${origin}/consent` } }),
			...(part.acr ? { acr: { values: part.acr.values } } : {}),
			...(part.documents ? { "clients-cimd": part.documents } : {}),
			// The back channel reaches the allowed origins alone, those on plain http at loopback as such;
			// the documents' hosts stay within reach beside them.
			...(part.logout
				? {
						outbound: {
							allow: [
								...part.logout.allowed.map((origin) => new URL(origin).hostname),
								...(part.documents?.allow ?? []),
							],
							"plain-loopback": part.logout.allowed
								.filter((origin) => origin.startsWith("http:"))
								.map((origin) => new URL(origin).host),
						},
					}
				: {}),
			...(part.refresh?.lifetimeSeconds
				? { refresh: { lifetime: `${part.refresh.lifetimeSeconds}s` } }
				: {}),
			...(part.sweepSeconds
				? { "session-lifecycle": { "sweep-interval": `${part.sweepSeconds}s` } }
				: {}),
		},
	};
});
