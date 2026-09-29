/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The `authorization_code` grant on session admission (the session-admission
 * ADR's D4, D8): both reads of the code's session go through `admitSession`
 * with `oauth.code_exchange` — the first, before anything is signed, with
 * `codeClaimFirstRead(code)` (a code carries no subject), the second, before
 * the family is linked, with `codeClaimRevalidation(code, <the first read's
 * sub>)`, so a subject that changed between the two reads stands refused as
 * `session_invalidated`. The pinned changes (4) and (5) are each a test named
 * for the change, on both reads.
 */

import crypto from "node:crypto";
import {
	type AppConfig,
	type AuditEvent,
	type ClientRepository,
	type CodeRepository,
	createInMemorySubjectRevocation,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantError,
	type RequirementInput,
	type RequirementVerdict,
	type SessionFamilyIndex,
	type SessionRequirement,
	type SessionRPRegistry,
	type SubjectRevocation,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { createMockLogger, type MockLogger } from "./_helpers/mockLogger.mjs";

const SID = "sid-1";
const SUBJECT = "user-1";
const CLIENT_ID = "client1";
const REDIRECT_URI = "https://rp.example/cb";
const VERIFIER = "pkce-verifier".padEnd(43, "x");
const CHALLENGE = crypto.createHash("sha256").update(VERIFIER).digest("base64url");

const config = {
	oauth: {
		jwt: { secret: "test-secret", issuer: "https://issuer.test" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: { authorization_code: { enabled: true } },
	},
} as unknown as AppConfig;

const minutesAgo = (minutes: number): Date => new Date(Date.now() - minutes * 60_000);

const record = (over: Partial<UserSession> = {}): UserSession => ({
	sid: SID,
	sub: SUBJECT,
	authTime: minutesAgo(5),
	createdAt: minutesAgo(5),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: {},
	amr: ["pwd"],
	authentication: {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	},
	...over,
});

/** A store answering each read in turn: the first read, then the revalidation. */
const storeAnswering = (
	...answers: ReadonlyArray<UserSession | null | Error>
): UserSessionStore & { get: ReturnType<typeof vi.fn> } => {
	let read = 0;
	return {
		kind: "memory",
		create: vi.fn(async () => {}),
		get: vi.fn(async () => {
			const answer = answers[Math.min(read++, answers.length - 1)];
			if (answer instanceof Error) throw answer;
			return answer ?? null;
		}),
		delete: vi.fn(async () => {}),
	} as unknown as UserSessionStore & { get: ReturnType<typeof vi.fn> };
};

const fixture = (
	verdict: () => RequirementVerdict,
): SessionRequirement & { readonly inputs: RequirementInput[] } => {
	const inputs: RequirementInput[] = [];
	return {
		name: "fixture",
		reach: new Set(),
		stepUpPage: { url: "/step-up", params: {} },
		remediations: ["fixture.step_up"],
		hintKeys: [],
		inputs,
		async admit(input) {
			inputs.push(input);
			return verdict();
		},
	};
};

const makeGrant = (opts: {
	userSessionStore?: UserSessionStore;
	subjectRevocation?: SubjectRevocation;
	requirements?: readonly SessionRequirement[];
	logger?: MockLogger;
	auditEvents?: AuditEvent[];
	/** Runs while the grant looks the client up, between the two reads. */
	betweenReads?: () => Promise<void>;
	sid?: string | undefined;
}) => {
	const codeRepository = {
		consumeByCode: vi.fn(async () =>
			codeRecord({
				code: "abc",
				client_id: CLIENT_ID,
				redirect_uri: REDIRECT_URI,
				code_challenge: CHALLENGE,
				code_challenge_method: "S256",
				grantedScope: ["openid"],
				sid: "sid" in opts ? opts.sid : SID,
			}),
		),
		createCode: vi.fn(),
		findByCode: vi.fn(),
		removeByCode: vi.fn(),
	} as unknown as CodeRepository;
	const clientRepository: ClientRepository = {
		findById: vi.fn(async () => {
			await opts.betweenReads?.();
			return null;
		}),
		authenticate: vi.fn(async () => null),
	};
	const sessionFamilyIndex = {
		kind: "memory",
		addFamilyId: vi.fn(async () => {}),
		listFamilyIds: vi.fn(async () => []),
		removeBySid: vi.fn(async () => {}),
	} as unknown as SessionFamilyIndex;
	const sessionRPRegistry = {
		kind: "memory",
		registerRP: vi.fn(async () => {}),
		listRPs: vi.fn(async () => []),
		removeBySid: vi.fn(async () => {}),
	} as unknown as SessionRPRegistry;
	const keyStore = createSymmetricKeyStore("test-secret");
	const signed = vi.spyOn(keyStore, "sign");
	const handler = createAuthorizationGrant({
		config,
		keyStore,
		codeRepository,
		clientRepository,
		sessionFamilyIndex,
		sessionRPRegistry,
		sessionRequirementResolver: resolverForTests(opts.requirements ?? [], {
			issuer: "https://issuer.test",
		}),
		...(opts.userSessionStore ? { userSessionStore: opts.userSessionStore } : {}),
		...(opts.subjectRevocation ? { subjectRevocation: opts.subjectRevocation } : {}),
		...(opts.logger ? { logger: opts.logger } : {}),
		...(opts.auditEvents
			? {
					auditSink: {
						kind: "recording",
						record: async (event: AuditEvent) => void opts.auditEvents?.push(event),
					},
				}
			: {}),
	});
	return { handler, signed, sessionFamilyIndex };
};

const ctx = (session: Record<string, unknown> = {}): GrantContext => ({
	body: { code: "abc", redirect_uri: REDIRECT_URI, code_verifier: VERIFIER },
	session,
	issuer: "https://issuer.test",
	metadata: {},
	authenticatedClient: { clientId: CLIENT_ID, tokenEndpointAuthMethod: "client_secret_basic" },
});

const refused = async (
	handler: ReturnType<typeof createAuthorizationGrant>,
): Promise<GrantError & { readonly step_up?: unknown }> => {
	const { result } = await handler.handle(ctx());
	expect("error" in result).toBe(true);
	return result as GrantError & { readonly step_up?: unknown };
};

describe("the authorization_code grant on admission — the first read (D8)", () => {
	it("(4) the subject-revocation boundary applies when subjectRevocation is wired: 400 invalid_grant session_invalid, nothing signed", async () => {
		const revocation = createInMemorySubjectRevocation();
		await revocation.revokeBefore(SUBJECT, new Date(), new Date(Date.now() + 3_600_000));
		const { handler, signed } = makeGrant({
			userSessionStore: storeAnswering(record()),
			subjectRevocation: revocation,
		});
		expect(await refused(handler)).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "session_invalid",
		});
		expect(signed).not.toHaveBeenCalled();
	});

	it("(5) a record past its expiresAt is 400 invalid_grant session_invalid, nothing signed", async () => {
		const { handler, signed } = makeGrant({
			userSessionStore: storeAnswering(record({ expiresAt: minutesAgo(1) })),
		});
		expect(await refused(handler)).toMatchObject({
			status: 400,
			errorDescription: "session_invalid",
		});
		expect(signed).not.toHaveBeenCalled();
	});

	it("keeps its answers for a code without sid and a session gone", async () => {
		expect(
			await refused(
				makeGrant({ userSessionStore: storeAnswering(record()), sid: undefined }).handler,
			),
		).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: expect.stringContaining("code record is missing session identifier (sid)"),
		});
		expect(
			await refused(makeGrant({ userSessionStore: storeAnswering(null) }).handler),
		).toMatchObject({ status: 400, errorDescription: "session_invalid" });
	});

	it("an outage is 503, logged once by admission with the action — not as the grant's user_session line", async () => {
		const logger = createMockLogger();
		const { handler } = makeGrant({
			logger,
			userSessionStore: storeAnswering(new Error("redis down")),
		});
		expect(await refused(handler)).toMatchObject({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "session store unavailable",
		});
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			{
				store: "user_session",
				action: "oauth.code_exchange",
				err: expect.objectContaining({ name: "Error" }),
			},
			"session_admission_unavailable",
		);
	});

	it("asks the requirements on both reads, with oauth.code_exchange over the code carrier", async () => {
		const requirement = fixture(() => ({ outcome: "met" }));
		const { handler } = makeGrant({
			userSessionStore: storeAnswering(record(), record()),
			requirements: [requirement],
		});
		const { result } = await handler.handle(ctx());
		expect(result.status).toBe(200);
		expect(requirement.inputs).toHaveLength(2);
		for (const input of requirement.inputs) {
			expect(input.action).toEqual({ name: "oauth.code_exchange", grade: "use" });
			expect(input.carrier).toBe("code");
			expect(input.subject).toBe(SUBJECT);
		}
	});

	it("step_up is 400 invalid_grant with step_up naming the requirement, nothing signed", async () => {
		const { handler, signed } = makeGrant({
			userSessionStore: storeAnswering(record()),
			requirements: [fixture(() => ({ outcome: "step_up", whenStillUnmet: "reauthenticate" }))],
		});
		expect(await refused(handler)).toMatchObject({
			status: 400,
			error: "invalid_grant",
			step_up: "fixture",
		});
		expect(signed).not.toHaveBeenCalled();
	});

	it("unmet and reauthenticate are 400 invalid_grant, with no step_up", async () => {
		for (const outcome of ["unmet", "reauthenticate"] as const) {
			const result = await refused(
				makeGrant({
					userSessionStore: storeAnswering(record()),
					requirements: [fixture(() => ({ outcome }))],
				}).handler,
			);
			expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
			expect(result.errorDescription).toMatch(/fixture/);
			expect(result.step_up).toBeUndefined();
		}
	});

	it("without a store, mints for the token request's cookie subject as before", async () => {
		const { handler } = makeGrant({});
		const { result } = await handler.handle(ctx({ user: { id: "cookie-user" } }));
		expect(result.status).toBe(200);
	});
});

describe("the authorization_code grant on admission — the revalidation (D8)", () => {
	it("a subject changed between the two reads is 400 session_invalidated, audited by admission and warned by the grant", async () => {
		const logger = createMockLogger();
		const auditEvents: AuditEvent[] = [];
		const { handler, sessionFamilyIndex } = makeGrant({
			logger,
			auditEvents,
			userSessionStore: storeAnswering(record(), record({ sub: "someone-else" })),
		});
		expect(await refused(handler)).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "session_invalidated",
		});
		expect(sessionFamilyIndex.addFamilyId).not.toHaveBeenCalled();
		expect(auditEvents.map((e) => e.type)).toEqual(["session.admission.subject_mismatch"]);
		expect(auditEvents[0]?.details).toMatchObject({ carrier: "code", claimedSubject: SUBJECT });
		expect(logger.warn).toHaveBeenCalledWith(
			{ sid: SID, clientId: CLIENT_ID },
			"authorization_grant_rejected_session_subject_changed_during_token_issuance",
		);
	});

	it("a session gone between the two reads is 400 session_invalidated, warned by the grant", async () => {
		const logger = createMockLogger();
		const { handler } = makeGrant({ logger, userSessionStore: storeAnswering(record(), null) });
		expect(await refused(handler)).toMatchObject({
			status: 400,
			errorDescription: "session_invalidated",
		});
		expect(logger.warn).toHaveBeenCalledWith(
			{ sid: SID, clientId: CLIENT_ID },
			"authorization_grant_rejected_session_invalidated_during_token_issuance",
		);
	});

	it("(5) a session that expired between the two reads is 400 session_invalidated", async () => {
		const { handler } = makeGrant({
			userSessionStore: storeAnswering(record(), record({ expiresAt: minutesAgo(1) })),
		});
		expect(await refused(handler)).toMatchObject({
			status: 400,
			errorDescription: "session_invalidated",
		});
	});

	it("(4) a boundary stamped between the two reads is 400 session_invalidated", async () => {
		const revocation = createInMemorySubjectRevocation();
		const { handler, sessionFamilyIndex } = makeGrant({
			userSessionStore: storeAnswering(record(), record()),
			subjectRevocation: revocation,
			betweenReads: () =>
				revocation.revokeBefore(SUBJECT, new Date(), new Date(Date.now() + 3_600_000)),
		});
		expect(await refused(handler)).toMatchObject({
			status: 400,
			errorDescription: "session_invalidated",
		});
		expect(sessionFamilyIndex.addFamilyId).not.toHaveBeenCalled();
	});

	it("an outage on the revalidation is 503, logged once by admission", async () => {
		const logger = createMockLogger();
		const { handler } = makeGrant({
			logger,
			userSessionStore: storeAnswering(record(), new Error("redis down")),
		});
		expect(await refused(handler)).toMatchObject({
			status: 503,
			errorDescription: "session store unavailable",
		});
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ store: "user_session", action: "oauth.code_exchange" }),
			"session_admission_unavailable",
		);
	});
});
