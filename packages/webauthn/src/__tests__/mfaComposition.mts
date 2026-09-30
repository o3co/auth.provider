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
 * The composition the WebAuthn second factor's flow tests boot through
 * `createApp`: the session package's login, the MFA package's modules over
 * core's memory MFA stores (or stores a test holds), this package's factor
 * module on, the user `alice`, and a recording audit sink; each section from
 * the builder of the package that owns it. A browser is driven over a
 * forwarded `https` hop with a cookie jar of its own, since the session
 * cookie is `Secure`. Not a test file.
 */

import { randomBytes } from "node:crypto";
import {
	type AppConfig,
	type AuditEvent,
	type AuditSink,
	createApp,
	createInMemoryUserSessionStore,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	createMemoryRateLimiter,
	defineModule,
	type FederationTokenStore,
	InMemoryUserRepository,
	type MfaFactorData,
	type MfaFactorRecord,
	type MfaFactorStore,
	type MfaTransactionStore,
	type Module,
	type SessionFederationIndex,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	CORE_RELOCATIONS,
	coreConfigForTests,
	makeValidAppConfig,
	renamedVariableCaptures,
} from "@o3co/auth-provider-core/testing";
import { mfaModule, mfaModules, mfaTotpFactorModule } from "@o3co/auth-provider-mfa";
import {
	mfaConfigForTests,
	mfaRecoveryCodeFactorConfigForTests,
	mfaTotpFactorConfigForTests,
	openMfaFactorDataForTests,
	seedMfaFactor,
} from "@o3co/auth-provider-mfa/testing";
import {
	loginCompletionModule,
	sessionModule,
	sessionStoreModuleFor,
} from "@o3co/auth-provider-session";
import express from "express";
import request from "supertest";
import { webauthnMfaFactorModule } from "#/mfaFactor/module.mjs";
import { createTestWebAuthnConfig, webauthnMfaFactorConfigForTests } from "#/testing/index.mjs";
import { type SoftwarePasskey, softwarePasskey } from "./softwarePasskey.mjs";

/** The relying party every flow runs against. */
export const RELYING_PARTY = createTestWebAuthnConfig();

/** A key of this suite's own: never the development sample key. */
const MFA_KEY = randomBytes(32).toString("base64");

/** The user the directory verifies. */
export const ALICE = {
	username: "alice",
	password: "alice-password-long",
	id: "u-alice",
	email: "alice@example.com",
} as const;

/** `mfa.lockout` as the MFA package's reference.conf resolves it. */
export const LOCKOUT = mfaConfigForTests({ key: MFA_KEY }).mfa.lockout;

/** The composition's configuration: MFA required, TOTP and WebAuthn on. */
export const CONFIG = {
	...makeValidAppConfig(),
	...coreConfigForTests({ expected: ["mfa"] }),
	...mfaConfigForTests({ key: MFA_KEY, mode: "required" }),
	...mfaTotpFactorConfigForTests(),
	...mfaRecoveryCodeFactorConfigForTests(),
	...webauthnMfaFactorConfigForTests({ enabled: true }),
	"renamed-variables": renamedVariableCaptures({
		modules: [mfaTotpFactorModule, mfaModule(), webauthnMfaFactorModule],
		core: CORE_RELOCATIONS,
		env: {},
	}),
} as unknown as AppConfig;

/** An audit sink that keeps what it is handed. */
export interface RecordingAuditSink extends AuditSink {
	/** The events of `type`, oldest first. */
	of(type: string): AuditEvent[];
}

function recordingAuditSink(): RecordingAuditSink {
	const events: AuditEvent[] = [];
	return {
		kind: "recording",
		of: (type) => events.filter((event) => event.type === type),
		async record(event) {
			events.push(event);
		},
	};
}

const providing = (name: string, provides: Record<string, () => unknown>): Module =>
	defineModule({ name, provides: provides as never });

export interface Composition {
	readonly app: express.Express;
	readonly audit: RecordingAuditSink;
	readonly factorStore: MfaFactorStore;
	readonly transactionStore: MfaTransactionStore;
	readonly userSessionStore: UserSessionStore;
}

const handles: { dispose(): Promise<void> }[] = [];

/** Disposes every composition booted since the last call. */
export const disposeAll = async (): Promise<void> => {
	await Promise.all(handles.splice(0).map((handle) => handle.dispose()));
};

/** Boots the composition over the stores given, or core's memory stores. */
export async function boot(
	stores: {
		readonly factorStore?: MfaFactorStore;
		readonly transactionStore?: MfaTransactionStore;
	} = {},
): Promise<Composition> {
	const factorStore = stores.factorStore ?? createMemoryMfaFactorStore();
	const transactionStore = stores.transactionStore ?? createMemoryMfaTransactionStore();
	const userSessionStore = createInMemoryUserSessionStore();
	const audit = recordingAuditSink();
	const handle = await createApp({
		modules: [
			sessionStoreModuleFor(CONFIG),
			sessionModule,
			loginCompletionModule,
			providing("test:user-repository", {
				userRepository: () =>
					new InMemoryUserRepository(
						new Map([
							[ALICE.username, { password: ALICE.password, id: ALICE.id, email: ALICE.email }],
						]),
					),
			}),
			providing("test:federation-token-store", {
				federationTokenStore: () =>
					({
						kind: "memory",
						attach: async () => {},
						get: async () => null,
						update: async () => {},
						removeBySid: async () => {},
						delete: async () => {},
					}) as unknown as FederationTokenStore,
			}),
			providing("test:session-federation-index", {
				sessionFederationIndex: () =>
					({
						kind: "memory",
						addFederation: async () => {},
						listFederations: async () => [],
						removeFederation: async () => {},
						removeBySid: async () => {},
					}) as unknown as SessionFederationIndex,
			}),
			providing("test:rate-limiter", {
				rateLimiter: () =>
					createMemoryRateLimiter({
						limits: {},
						defaultLimit: { limit: 1000, windowSeconds: 60 },
					}),
			}),
			providing("test:user-session-store", { userSessionStore: () => userSessionStore }),
			providing("test:mfa-factor-store", { mfaFactorStore: () => factorStore }),
			providing("test:mfa-transaction-store", { mfaTransactionStore: () => transactionStore }),
			...mfaModules({ environment: "development" }),
			providing("test:webauthn-config", { webauthnConfig: () => RELYING_PARTY }),
			webauthnMfaFactorModule,
		],
		bootstrapComponents: {
			config: CONFIG,
			pathResolver: (s: string) => s,
			auditSink: audit,
		} as never,
	});
	handles.push(handle);
	// The session cookie is `Secure`: the browser reaches the provider over a forwarded https hop.
	const app = express().set("trust proxy", "loopback").use(handle.router);
	return { app, audit, factorStore, transactionStore, userSessionStore };
}

/** A software passkey for {@link RELYING_PARTY}. */
export const passkeyFor = (
	options: { readonly backedUp?: boolean; readonly counter?: number | "none" } = {},
): SoftwarePasskey =>
	softwarePasskey({
		rpId: RELYING_PARTY.rpId,
		origin: RELYING_PARTY.origin[0] as string,
		...options,
	});

/** The subject's WebAuthn user handle every seeded factor carries. */
export const USER_HANDLE = randomBytes(32).toString("base64url");

/** Seeds `passkey` as one of alice's WebAuthn factors, its data sealed under the composition's key ring, at `signCount`. */
export async function seedPasskey(
	factorStore: MfaFactorStore,
	passkey: SoftwarePasskey,
	signCount: number = passkey.counter,
): Promise<MfaFactorRecord> {
	return seedMfaFactor({
		config: CONFIG,
		factorStore,
		subject: ALICE.id,
		kind: "webauthn",
		data: {
			credentialId: passkey.credentialId,
			publicKey: passkey.publicKey,
			signCount,
			transports: ["internal"],
			backedUp: passkey.backedUp,
			userHandle: USER_HANDLE,
		},
	});
}

/** The record and its opened data, as the factor store now holds them. */
export async function storedFactor(
	factorStore: MfaFactorStore,
	record: Pick<MfaFactorRecord, "subject" | "id">,
): Promise<{ readonly record: MfaFactorRecord; readonly data: MfaFactorData }> {
	const stored = (await factorStore.list(record.subject)).find((entry) => entry.id === record.id);
	if (stored === undefined) throw new Error("the factor is gone");
	return { record: stored, data: openMfaFactorDataForTests(CONFIG, stored) };
}

/** A browser on the composition. */
export interface Browser {
	get(path: string, headers?: Record<string, string>): Promise<request.Response>;
	/** A POST as the page sends it: a fresh CSRF token, then the JSON body. */
	post(path: string, body: Record<string, unknown>): Promise<request.Response>;
}

/** A browser on the composition: its cookies kept and sent back, over the forwarded https hop. */
export function browser(app: express.Express): Browser {
	const jar = new Map<string, string>();
	const keep = (res: request.Response): request.Response => {
		for (const line of ([] as string[]).concat(res.headers["set-cookie"] ?? [])) {
			const pair = line.split(";")[0] ?? "";
			jar.set(pair.slice(0, pair.indexOf("=")), pair);
		}
		return res;
	};
	const headers = () => ({ Cookie: [...jar.values()].join("; "), "X-Forwarded-Proto": "https" });
	const get = async (
		path: string,
		extra: Record<string, string> = {},
	): Promise<request.Response> => keep(await request(app).get(path).set(headers()).set(extra));
	const post = async (path: string, body: Record<string, unknown>): Promise<request.Response> => {
		const csrf = await get("/session/csrf");
		return keep(
			await request(app)
				.post(path)
				.set(headers())
				.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
				.send(body),
		);
	};
	return { get, post };
}

/** alice's password login, answered 403 mfa_required: the browser holding the regenerated session, and the transaction. */
export async function beginLogin(
	app: express.Express,
): Promise<{ readonly browser: Browser; readonly transaction: string }> {
	const agent = browser(app);
	const res = await agent.post("/session/login", {
		username: ALICE.username,
		password: ALICE.password,
	});
	if (res.status !== 403 || res.body.error !== "mfa_required") {
		throw new Error(`the login answered ${res.status} ${JSON.stringify(res.body)}`);
	}
	return { browser: agent, transaction: res.body.transaction as string };
}

/** `POST /session/mfa/challenge` for `factorId`: the request options it answers. */
export const challenge = (
	agent: Browser,
	transaction: string,
	factorId: string,
): Promise<request.Response> =>
	agent.post("/session/mfa/challenge", { transaction_id: transaction, factor_id: factorId });

/** `POST /session/mfa/verify` of `proof` for `factorId`. */
export const verify = (
	agent: Browser,
	transaction: string,
	factorId: string,
	proof: unknown,
): Promise<request.Response> =>
	agent.post("/session/mfa/verify", { transaction_id: transaction, factor_id: factorId, proof });
