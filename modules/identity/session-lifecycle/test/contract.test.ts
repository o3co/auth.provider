import cookiesModule from "@mod/cookies/module";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { sessions } from "@mod/session";
import { type PlaceOptions, type SessionsPlace, sessionsContract } from "@mod/session/testing";
import { participants } from "@mod/session-participants";
import sessionParticipants from "@mod/session-participants/module";
import { entryRequirements } from "@mod/session-requirements";
import sessionRequirements from "@mod/session-requirements/module";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { describe, expect, it } from "vitest";
import { defaultLifetimeSeconds } from "../src/limits.ts";
import sessionLifecycle from "../src/module.ts";
import { sessionLifecycleConfig } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

/** A place over session-lifecycle and the given modules, with the requirement and participant the contract test expects. */
async function placeOver(
	modules: readonly Module[],
	{ credentialsJudged = true }: PlaceOptions = {},
): Promise<SessionsPlace> {
	let now = 1_800_000_000_000;
	let failing = false;
	const closed: string[] = [];
	const stores = memoryStores();
	const around = defineModule({ name: "around", takes: [] }, (m) => [
		// Where credentials are judged, only a strong login changes them.
		...(credentialsJudged
			? [
					m.contribute(entryRequirements).by(() => ({
						name: "test",
						judges: ["credentials"],
						admits: async (context, level) =>
							level === "credentials" && !context.amr.includes("strong")
								? { kind: "short", answer: { error: "short" } }
								: { kind: "admit" },
					})),
				]
			: []),
		m.contribute(participants).by(() => ({
			name: "test",
			closing: async (session) => {
				if (failing) throw new Error("not yet");
				closed.push(session.context.subject);
			},
		})),
	]);
	const app = await assemble({
		modules: [
			http,
			cookiesModule,
			sessionLifecycle,
			sessionRequirements,
			sessionParticipants,
			stores.module,
			subjectRevocationStandIn,
			...modules,
			around,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			...sessionLifecycleConfig(),
		},
		runtime: quietRuntime({ clock: { now: () => now } }),
	});
	return {
		sessions: app.get(sessions),
		now: () => now,
		advance: (ms) => {
			now += ms;
		},
		lifetimeMs: defaultLifetimeSeconds * 1000,
		request: (setCookies = []) =>
			testRequest({
				headers: new Map([["cookie", setCookies.map((c) => c.split(";")[0]).join("; ")]]),
				source: { scheme: "https" },
			}),
		revokeSubject: (subject) => app.get(revocations).record(subject),
		closed,
		failClosing: (on) => {
			failing = on;
		},
		listingCap: stores.listingCap,
		failNextListing: () => stores.down.listed.failNext("add"),
		betweenCookieAndSession: (meanwhile) => {
			stores.afterIndexRead.next = meanwhile;
		},
	};
}

sessionsContract(
	"session-lifecycle over the records stand-in and subject-revocation's stand-in",
	(options) => placeOver([], options),
);

const login = (place: SessionsPlace) =>
	place.sessions.complete(place.request(), {
		subject: "alice",
		amr: ["pwd"],
		authenticatedAt: place.now(),
	});

describe("entry requirements", () => {
	it("are asked in name order", async () => {
		const asked: string[] = [];
		const requirement = (name: string) => ({
			name,
			judges: ["use" as const],
			admits: async () => {
				asked.push(name);
				return { kind: "admit" as const };
			},
		});
		const unsorted = defineModule({ name: "unsorted", takes: [] }, (m) => [
			m.contribute(entryRequirements).by(() => requirement("b")),
			m.contribute(entryRequirements).by(() => requirement("a")),
		]);
		const place = await placeOver([unsorted]);
		const done = await login(place);
		asked.length = 0;
		expect((await place.sessions.enterFor(place.request(done.cookies), "use")).kind).toBe(
			"entered",
		);
		expect(asked).toEqual(["a", "b"]);
	});
});

describe("participants", () => {
	it("are called one at a time in the order collected, past a failing one", async () => {
		const calls: string[] = [];
		let running = 0;
		let overlapped = false;
		const participant = (name: string, fails: boolean) => ({
			name,
			closing: async () => {
				running++;
				overlapped ||= running > 1;
				calls.push(name);
				await new Promise((resolve) => setTimeout(resolve, 5));
				running--;
				if (fails) throw new Error("not yet");
			},
		});
		const two = defineModule({ name: "two", takes: [] }, (m) => [
			m.contribute(participants).by(() => participant("b", true)),
			m.contribute(participants).by(() => participant("a", false)),
		]);
		const place = await placeOver([two]);
		const done = await login(place);
		expect((await place.sessions.close(done.session.id)).kind).toBe("pending");
		expect(calls).toEqual(["b", "a"]);
		expect(place.closed).toEqual(["alice"]);
		expect(overlapped).toBe(false);
	});
});
