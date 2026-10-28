import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import clientsModule from "@mod/clients/module";
import {
	clientSecret,
	clientsConfig,
	confidentialClient,
	publicClient,
} from "@mod/clients/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, recordingLog, switchedModule, unavailableSwitch } from "@mod/kernel/testing";
import rateLimitModule from "@mod/rate-limit/module";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import secretHashModule from "@mod/secret-hash/module";
import { simulatedStore } from "@mod/store/testing";
import { grantCaller } from "@mod/token-endpoint/testing";
import { type IssueLimits, type Tokens, tokens } from "@mod/tokens";
import { type TokensSettings, tokensStandIn } from "@mod/tokens/testing";
import { afterEach } from "vitest";
import tokenControl from "../src/module.ts";

const logged = recordingLog();
/** The composition's clock: fixed where the tests start, moved on only by `later`, so no boundary rests on real time. */
const startedAt = Date.now();
let ahead = 0;
/** What the composition's clock reads now. */
export const clockNow = () => startedAt + ahead;
const runtime = quietRuntime({ log: logged.log, clock: { now: clockNow } });
const confidential = (id: string, audiences: string[], grants: string[] = []) =>
	confidentialClient({
		id,
		sections: allowancesFor({ grants, scopes: ["read"], "default-scopes": ["read"], audiences }),
	});

let stop = async () => {};
afterEach(() => {
	ahead = 0;
	return stop();
});

/** Moves the composition's clock on by this much. */
export const later = (ms: number) => {
	ahead += ms;
};

export type Form = Record<string, string> | [string, string][];

/**
 * token-control over the tokens stand-in. "app" holds the client credentials grant for
 * https://api, "api" shares that audience, "other" sees another, and "pub" is public.
 * `limit` sets token-control's section and counts requests for real; otherwise nothing is limited.
 */
export async function serve(
	options: {
		revocation?: TokensSettings["revocation"];
		extra?: Module[];
		http?: Record<string, unknown>;
		limit?: Record<string, unknown>;
	} = {},
) {
	const down = unavailableSwitch<Tokens>("tokens");
	const recorded = auditStandIn();
	const revocable = (options.revocation ?? "denylist") === "denylist";
	const app = await assemble({
		modules: [
			http,
			switchedModule(tokensStandIn({ revocable }), tokens, down),
			issuerModule,
			clientsModule,
			secretHashModule,
			grantCaller,
			clientAllowanceModule,
			tokenControl,
			recorded.module,
			...(options.limit ? [rateLimitModule, simulatedStore().module] : [rateLimitStandIn]),
			...(options.extra ?? []),
		],
		config: {
			...kernelConfig(),
			...httpConfig(options.http ?? {}),
			...issuerConfig({ url: "https://issuer.example" }),
			...clientsConfig([
				confidential("app", ["https://api"], ["client_credentials"]),
				confidential("api", ["https://api"]),
				confidential("other", ["https://elsewhere"]),
				publicClient({ id: "pub" }),
			]),
			...(options.limit ? { "token-control": options.limit } : {}),
		},
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	/** Posts `form` as client `as`, or as the form's own credentials when `as` is undefined. */
	const post = async (path: string, as: string | undefined, form: Form) => {
		const body = new URLSearchParams(form);
		if (as !== undefined) {
			body.append("client_id", as);
			body.append("client_secret", clientSecret(as));
		}
		const res = await fetch(`${base}${path}`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body,
		});
		const text = await res.text();
		const json = (text === "" ? {} : JSON.parse(text)) as Record<string, unknown>;
		return { status: res.status, headers: res.headers, text, json, error: json.error };
	};
	// What the client credentials grant gives "app": its audience and default scope.
	const grant = { subject: "app", issuedTo: "app", audience: ["https://api"], scope: ["read"] };
	const issue = async (limits?: IssueLimits) => {
		const issued = await app.get(tokens).issue({ grant, grantType: "client_credentials" }, limits);
		if (issued.kind !== "issued") throw new Error(issued.reason);
		return issued.access.token;
	};
	const active = async (token: string) =>
		(await post("/oauth/introspect", "app", { token })).json.active as boolean;
	/** The warnings logged since this composition was made. */
	const from = logged.lines().length;
	const warnings = () =>
		logged
			.lines()
			.slice(from)
			.filter((line) => line.level === "warn")
			.map((line) => [line.event, line.fields]);
	return { base, post, issue, active, down, events: recorded.events, warnings };
}
