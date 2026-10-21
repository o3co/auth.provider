import { defineModule, Unavailable } from "@mod/kernel";
import {
	type AuthorizationStart,
	type CodeExchange,
	idpType,
	idpTypes,
	type Upstream,
	type UpstreamLogin,
	UpstreamMismatch,
	UpstreamRefused,
} from "@mod/upstreams";
import { z } from "zod";
import type { section } from "./section.ts";

export type FederationSettings = z.input<typeof section>;

export function federationConfig(settings: Partial<FederationSettings> = {}) {
	return { federation: settings };
}

/**
 * An IdP type for tests, "test": its upstream at `issuer` answers a code with the login the
 * test gave it (or fails as `unreachable` or `broken` says, or refuses as another copy of
 * upstreams would where it says `copied`), refuses any other code, and keeps
 * what it was asked; it offers what `more` gives.
 */
export function testIdpType(
	answers: Map<string, UpstreamLogin | "unreachable" | "broken" | "copied">,
	more: Pick<Upstream, "refresh" | "endSession" | "delegation"> = {},
) {
	const asked = { starts: [] as AuthorizationStart[], exchanges: [] as CodeExchange[] };
	const module = defineModule({ name: "test-idp-type" }, (m) => [
		m.contribute(idpTypes).by(() =>
			idpType({
				type: "test",
				settings: z.strictObject({
					issuer: z.url(),
					path: z.string().default("/authorize"),
					mode: z.enum(["query", "form_post"]).default("query"),
					"skew-ms": z.number().default(30_000),
					/** The type refuses its settings, so a test can see a boolean read. */
					refuses: z.boolean().default(false),
				}),
				open: async (read) => {
					const { issuer, path, mode } = read;
					if (issuer.includes("mismatch")) throw new Error("not this upstream");
					if (issuer.includes("unreachable")) throw new Unavailable("test upstream");
					if (read.refuses) throw new UpstreamMismatch("refused by its settings", ["refuses"]);
					// As another copy of upstreams in the bundle would throw it: another class, the same mark.
					if (issuer.includes("copied")) {
						throw Object.assign(new Error("the description names another issuer"), {
							at: ["issuer"],
							[Symbol.for("@mod/upstreams.mismatch")]: true,
						});
					}
					if (issuer.includes("misdescribed")) {
						throw new UpstreamMismatch("the description names another issuer", ["issuer"]);
					}
					return {
						...more,
						issuer,
						responseMode: mode,
						clockSkewMs: read["skew-ms"],
						authorizationUrl: (start) => {
							asked.starts.push(start);
							const url = new URL(`${issuer}${path}`);
							url.searchParams.set("state", start.state);
							return url.href;
						},
						exchange: async (exchange) => {
							asked.exchanges.push(exchange);
							const found = answers.get(exchange.code);
							if (found === "unreachable") throw new Unavailable("test upstream");
							if (found === "broken") throw new Error("test upstream");
							if (found === "copied") {
								throw Object.assign(new Error("upstream refused"), {
									[Symbol.for("@mod/upstreams.refused")]: true,
								});
							}
							if (!found) throw new UpstreamRefused();
							return found;
						},
					};
				},
			}),
		),
	]);
	return { module, asked };
}
