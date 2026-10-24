import { cookies } from "@mod/cookies";
import { applying, marks, policies, type Site, site } from "@mod/http";
import { contract, type Parts } from "@mod/kernel";
import { checking, sameOriginOf } from "./check.ts";
import { csrfChecked, csrfRefused, originEvidence } from "./contract.ts";

/** The public origin both checks compare with, refused once without one. */
const ours = contract<Site>("csrf.public-origin");

/**
 * The policy's rule, its mark and the origin evidence, built alike by the module and its stand-in.
 * Without a public origin the module refuses boot. The stand-in refuses every unsafe request
 * instead, until no test boots it without one.
 */
/** What `deciding` takes from other modules: the site, and cookies for the token it checks. */
export const decidingTakes = [cookies, site] as const;

export const deciding = (m: Parts<undefined>, withoutOrigin: "refuse boot" | "refuse requests") => [
	m.provide(ours).by(async (c) => {
		const publicSite = await c.get(site);
		if (publicSite.origin === undefined && withoutOrigin === "refuse boot")
			return c.refuse("csrf", "a public origin is required");
		return publicSite;
	}),
	m.provide(originEvidence).by(async (c) => {
		const { origin, secureCookies } = await c.get(ours);
		return { sameOrigin: origin === undefined ? () => false : sameOriginOf(origin, secureCookies) };
	}),
	m.contribute(policies).by(async (c) => {
		const { origin, secureCookies } = await c.get(ours);
		const check =
			origin === undefined
				? () => "refused"
				: checking(origin, secureCookies, await c.get(cookies));
		return applying(csrfChecked, (request) =>
			request.method === "GET" || check(request) === "passed" ? "pass" : csrfRefused,
		);
	}),
	m.contribute(marks).by(() => ({
		guarantee: "own-site",
		policies: [{ policy: csrfChecked, methods: ["POST", "PUT", "DELETE"] }],
	})),
];
