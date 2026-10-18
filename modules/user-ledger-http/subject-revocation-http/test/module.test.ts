import { auditStandIn } from "@mod/audit/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { afterEach, describe, expect, it } from "vitest";
import revocationModule from "../src/module.ts";

const credential = "Kq3vX9pLm2Rt7Yw4Nc8Bz1Hd6Fj0Gs5Ua-Ve_Io2LxM";
const runtime = quietRuntime();
let stop = async () => {};
afterEach(() => stop());

/** The route behind http, trusting the local proxy unless told otherwise. */
async function serve(
	settings: Record<string, unknown> = {},
	proxies: readonly string[] = ["127.0.0.1"],
) {
	const audit = auditStandIn();
	const app = await assemble({
		modules: [http, audit.module, rateLimitStandIn, subjectRevocationStandIn, revocationModule],
		config: {
			...kernelConfig(),
			...httpConfig({ "trusted-proxies": [...proxies] }),
			"subject-revocation-http": { credential, sources: ["198.51.100.0/24"], ...settings },
		},
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const post = (body: string, headers: Record<string, string> = {}) =>
		fetch(`http://127.0.0.1:${app.get(listening).port()}/ledger/subject-revocations`, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				"x-forwarded-for": "198.51.100.7",
				"x-forwarded-proto": "https",
				authorization: `Bearer ${credential}`,
				...headers,
			},
			body,
		});
	return { app, post, events: audit.events };
}

describe("subject-revocation-http", () => {
	it("revokes a subject the ledger names over https from a listed source", async () => {
		const { app, post, events } = await serve();
		const before = runtime.clock.now() - 1;
		const answer = await post(JSON.stringify({ subject: "alice" }));
		expect([answer.status, await answer.json()]).toEqual([200, { complete: true }]);
		expect(await app.get(revocations).compare("alice", before, "sessions")).toBe("revoked");
		expect(await app.get(revocations).compare("alice", before, "delegations")).toBe("revoked");
		expect(events.map((e) => [e.kind, e.subject, e.attributes])).toEqual([
			[
				"subject.revocation.requested",
				"alice",
				{ delegations: "end", outcome: "complete", source: "198.51.100.7" },
			],
		]);
	});

	it("takes the previous credential while it is set, for moving the ledger to a new one", async () => {
		const previous = "Wn5Tb8Qr1Ms4Kd7Hf0Jg3Lc6Pz9Xv2Yu-Ea_Ri5OkPq";
		const { post } = await serve({ "previous-credential": previous });
		const answer = await post(JSON.stringify({ subject: "alice" }), {
			authorization: `Bearer ${previous}`,
		});
		expect(answer.status).toBe(200);
		expect((await post(JSON.stringify({ subject: "alice" }))).status).toBe(200);
	});

	it("leaves an unreadable, a non-JSON or a form body to http, before any check and unrecorded", async () => {
		const { post, events } = await serve();
		expect((await post("{")).status).toBe(400);
		expect((await post("subject=alice", { "content-type": "text/plain" })).status).toBe(415);
		expect(
			(await post("subject=alice", { "content-type": "application/x-www-form-urlencoded" })).status,
		).toBe(415);
		expect(events).toEqual([]);
	});

	it("refuses boot behind no proxy it trusts, as no request could be told as https", async () => {
		await expect(serve({}, [])).rejects.toBeInstanceOf(BootRefused);
	});

	it("refuses boot on a credential or sources it cannot use", async () => {
		const refused = [
			{ credential: undefined },
			{ credential: "short-token" },
			{ "previous-credential": "short-token" },
			{ sources: [] },
			{ sources: ["not-an-address"] },
			{ failures: 0 },
			{ window: "500ms" },
			{ "failure-window": "2h" },
			{ unknown: true },
		];
		for (const settings of refused) {
			await expect(serve(settings), JSON.stringify(settings)).rejects.toBeInstanceOf(BootRefused);
		}
	});
});
