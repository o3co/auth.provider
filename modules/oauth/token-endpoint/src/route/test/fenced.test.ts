import { auditStandIn } from "@mod/audit/testing";
import clientAllowanceModule from "@mod/client-allowance/module";
import { allowancesFor } from "@mod/client-allowance/testing";
import { clientsConfig, confidentialClient } from "@mod/clients/testing";
import { type Grant, grants } from "@mod/grants";
import { listening } from "@mod/http";
import { assemble, defineModule, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import rateLimitModule from "@mod/rate-limit/module";
import { simulatedStore } from "@mod/store/testing";
import { type FencedBundle, issuanceFences, issuancePolicies } from "@mod/tokens";
import { afterEach, expect, it } from "vitest";
import { basicOf, endpointConfig, endpointModules } from "../../../test/deployment.ts";

let stop = async () => {};
afterEach(() => stop());

/** A grant answering a bundle issued under `subjects`, one token each, with no `issue` when none. */
const issuing = (grantType: string, subjects: readonly string[]): Grant => ({
	grantType,
	readsAmbient: "none",
	handle: async ({ client, issue }) => {
		const tokens: string[] = [];
		for (const subject of subjects) {
			const issued = await issue({ subject, issuedTo: client.id, audience: [], scope: [] });
			if (issued.kind !== "issued") return issued;
			tokens.push(issued.access.token);
		}
		return {
			kind: "issued",
			body: { access_token: tokens.join(" ") || "none", token_type: "Bearer" },
		};
	},
});

/** The endpoint with one fence answering `answer` for a subject, noting each bundle it is asked. */
async function serve(answer: (subject: string) => "passed" | "refused" | "unavailable") {
	const asked: FencedBundle[] = [];
	const fence = defineModule({ name: "fence", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(issuanceFences).by(() => ({
			name: "test-fence",
			fence: async (bundle) => {
				asked.push(bundle);
				const answered = answer(bundle.subject);
				if (answered === "unavailable") throw new Unavailable("test-fence");
				return answered;
			},
		})),
		m.contribute(grants).by(() => issuing("urn:test:two", ["alice", "bob"])),
		m.contribute(grants).by(() => issuing("urn:test:none", [])),
		m.contribute(grants).by(() => issuing("urn:test:judged", ["judged"])),
		// Refuses "judged" with an answer it cannot read, which tokens refuses as unreadable.
		m.contribute(issuancePolicies).by(() => ({
			name: "unreadable",
			judge: async ({ grant }) =>
				grant.subject === "judged" ? ({} as never) : { kind: "allowed" },
		})),
	]);
	const recorded = auditStandIn();
	const sections = allowancesFor({
		grants: ["client_credentials", "urn:test:two", "urn:test:none", "urn:test:judged"],
		scopes: ["read"],
		"default-scopes": ["read"],
	});
	const app = await assemble({
		modules: endpointModules(
			clientAllowanceModule,
			rateLimitModule,
			recorded.module,
			simulatedStore().module,
			fence,
		),
		config: {
			...endpointConfig({ issuer: "https://issuer.example" }),
			...clientsConfig([
				confidentialClient({ id: "basic", method: "client_secret_basic", sections }),
			]),
		},
		runtime: quietRuntime(),
	});
	await app.start();
	stop = () => app.stop(1000);
	const url = `http://127.0.0.1:${app.get(listening).port()}/oauth/token`;
	const sent = (grantType: string) =>
		fetch(url, {
			method: "POST",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				authorization: basicOf("basic", "basic-secret"),
			},
			body: new URLSearchParams({ grant_type: grantType }),
		});
	const post = async (grantType: string) => {
		const res = await sent(grantType);
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};
	/** The whole answer as sent, but its date. */
	const whole = async (grantType: string) => {
		const res = await sent(grantType);
		const headers = Object.fromEntries([...res.headers].filter(([name]) => name !== "date"));
		return { status: res.status, headers, body: await res.text() };
	};
	const events = () => recorded.events.map(({ kind, attributes }) => ({ kind, attributes }));
	return { post, whole, asked, events };
}

it("answers a bundle its fence passes, the fence asked once with the subject issued under", async () => {
	const { post, asked, events } = await serve(() => "passed");
	const answered = await post("client_credentials");
	expect(answered.status).toBe(200);
	expect(answered.body.access_token).toEqual(expect.any(String));
	expect(asked).toEqual([{ subject: "basic", receiptId: expect.any(String) }]);
	expect(events().map((e) => e.kind)).toEqual(["token.issued"]);
});

it("answers none of a bundle its fence refuses, as any refused issuance, and records the fence", async () => {
	const { post, events } = await serve(() => "refused");
	expect(await post("client_credentials")).toEqual({
		status: 400,
		body: { error: "invalid_grant", error_description: "issuance refused" },
	});
	expect(events()).toEqual([
		{
			kind: "token.issued.failure",
			attributes: expect.objectContaining({
				client: "basic",
				grant_type: "client_credentials",
				reason: "issuance_fenced",
				error: "invalid_grant",
				fence: "test-fence",
			}),
		},
	]);
	// A fence is never named as a policy, which judges before signing.
	expect(events()[0]?.attributes).not.toHaveProperty("policy");
});

it("answers a fenced bundle exactly as an issuance a policy refused, headers and all", async () => {
	const { whole, events } = await serve(() => "refused");
	const judged = await whole("urn:test:judged");
	expect(events().map((e) => e.attributes?.reason)).toEqual(["issuance_refused"]);
	expect(await whole("client_credentials")).toEqual(judged);
	expect(events().map((e) => e.attributes?.reason)).toEqual([
		"issuance_refused",
		"issuance_fenced",
	]);
});

it("is unavailable where its fence cannot tell, recording nothing", async () => {
	const { post, events } = await serve(() => "unavailable");
	expect(await post("client_credentials")).toEqual({
		status: 503,
		body: { error: "temporarily_unavailable" },
	});
	expect(events()).toEqual([]);
});

it("answers none of a bundle issued under no subject or more than one, a grant's fault, its fence not asked", async () => {
	const { whole, asked, events } = await serve(() => "passed");
	for (const grantType of ["urn:test:none", "urn:test:two"]) {
		const answered = await whole(grantType);
		expect(answered.status).toBe(500);
		expect(answered.body).not.toMatch(/token|alice|bob/);
	}
	expect(asked).toEqual([]);
	expect(events()).toEqual([]);
});
