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
 * A client reaching `GET /authorize` must be marked `firstParty: true`.
 * Minting a code for any registered client once `req.session.isAuthenticated`
 * is true is defensible only in a pure first-party OP; one semi-trusted client
 * would turn the endpoint into an account-linking vector. The removed
 * `oauth.authorize.allowUnmarkedClients` flag has no effect: boot refuses it,
 * as a path the oauth module's manifest declares removed, before any schema
 * runs; a hand-built config handed to the router bypasses boot, so the handler
 * must not read it either.
 *
 * Not pinned: "forced navigation is impossible" — it is not. A client marked
 * first-party still mints a code on a forced top-level navigation; that is the
 * accepted model, and consent is the user-interaction step that changes it.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type AppConfig,
	ClientEntrySchema,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantHandler,
	InMemoryClientRepository,
	loadYamlMap,
	type PublicClient,
} from "@o3co/auth-provider-core";
import {
	createTestLoginEntry,
	GrantRegistry,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { routerInputsOf } from "./_helpers/sections.mjs";

const CLIENT_ID = "client-a";
const REDIRECT_URI = "https://app.example/cb";

const makeConfig = (staleAllowUnmarkedClients: boolean): AppConfig =>
	({
		oauth: {
			jwt: { issuer: "https://issuer.example" },
			accessToken: { expiresIn: 300 },
			// A schema-validated config cannot carry the removed flag, but a
			// hand-built one can — injecting it here pins that the stale key is
			// inert rather than merely absent from fixtures.
			...(staleAllowUnmarkedClients ? { authorize: { allowUnmarkedClients: true } } : {}),
			grants: { authorization_code: { enabled: true } },
		},
		rateLimit: { failMode: "open" as const },
		endpoints: { login: { url: "/login" } },
	}) as unknown as AppConfig;

const alwaysGrant = (): GrantHandler => ({
	async handle() {
		return {
			result: { status: 200, tokens: { access_token: "at", token_type: "Bearer" } },
		};
	},
});

const makeApp = async (opts: {
	firstParty?: boolean;
	/** Injects the REMOVED `oauth.authorize.allowUnmarkedClients: true`. */
	staleAllowUnmarkedClients?: boolean;
	warn?: ReturnType<typeof vi.fn>;
}) => {
	const record = {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "none" as const,
		allowedRedirectUris: [REDIRECT_URI],
		allowedScopes: ["read"],
		...(opts.firstParty === undefined ? {} : { firstParty: opts.firstParty }),
	} as unknown as PublicClient;

	const clientRepository: ClientRepository = {
		findById: async (id) => (id === CLIENT_ID ? record : null),
		authenticate: async () => null,
	};
	const codeRepository: CodeRepository = {
		createCode: async () =>
			codeRecord({ code: "code-x", client_id: CLIENT_ID, redirect_uri: REDIRECT_URI }),
		findByCode: async () => null,
		consumeByCode: async () => null,
		removeByCode: async () => {},
	};

	const registry = new GrantRegistry();
	registry.register("authorization_code", alwaysGrant());

	const { router } = await createOAuthRouter(express, {
		loginEntry: createTestLoginEntry(),
		requirements: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		registry,
		...routerInputsOf(makeConfig(opts.staleAllowUnmarkedClients ?? false)),
		clientRepository,
		codeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		...(opts.warn
			? {
					logger: {
						warn: opts.warn,
						info: vi.fn(),
						error: vi.fn(),
						debug: vi.fn(),
					} as never,
				}
			: {}),
	});

	const app = express();
	app.use(express.json());
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = {
			isAuthenticated: true,
			user: { id: "user-1" },
		};
		next();
	});
	app.use("/oauth", router);
	return app;
};

const authorize = (app: express.Express) =>
	request(app).get("/oauth/authorize").query({
		response_type: "code",
		client_id: CLIENT_ID,
		redirect_uri: REDIRECT_URI,
		state: "xyz",
		code_challenge: "abc",
		code_challenge_method: "plain",
	});

/** The `error` a response carries, wherever it carries it. */
const errorOf = (res: request.Response): string | null => {
	const location = res.headers.location as string | undefined;
	if (location !== undefined) {
		try {
			return new URL(location).searchParams.get("error");
		} catch {
			return null;
		}
	}
	return typeof res.body?.error === "string" ? res.body.error : null;
};

describe("/authorize first-party invariant", () => {
	it("refuses a client that is not marked first-party", async () => {
		const app = await makeApp({ firstParty: undefined });
		expect(errorOf(await authorize(app))).toBe("unauthorized_client");
	});

	it("refuses a client explicitly marked not first-party", async () => {
		const app = await makeApp({ firstParty: false });
		expect(errorOf(await authorize(app))).toBe("unauthorized_client");
	});

	it("admits a client marked first-party", async () => {
		const app = await makeApp({ firstParty: true });
		expect(errorOf(await authorize(app))).not.toBe("unauthorized_client");
	});

	it("delivers the refusal as a redirect to the registered redirect_uri", async () => {
		// `redirect_uri` is validated against the client's allowlist before this
		// check, so the error goes to the real client and no code is minted.
		// RFC 6749 §4.1.2.1 puts errors after that validation in the redirect.
		const app = await makeApp({ firstParty: false });
		const res = await authorize(app);
		expect(res.status).toBe(302);
		const location = new URL(res.headers.location as string);
		expect(location.origin + location.pathname).toBe(REDIRECT_URI);
		expect(location.searchParams.get("state")).toBe("xyz");
		expect(location.searchParams.get("code")).toBeNull();
	});
});

describe("/authorize first-party invariant — the removed migration flag has no effect", () => {
	it("refuses an unmarked client even when a config still carries the removed flag", async () => {
		// A schema-validated config cannot reach here with the key (the schema
		// rejects it at boot); a hand-built config can, and it must be inert.
		const app = await makeApp({ firstParty: undefined, staleAllowUnmarkedClients: true });
		expect(errorOf(await authorize(app))).toBe("unauthorized_client");
	});

	it("emits no admission warning — the migration code path is gone, not just off", async () => {
		// With no unmarked client admitted there is nothing to warn about; the
		// refusal is what surfaces (audit `client_not_first_party`).
		const warn = vi.fn();
		const app = await makeApp({
			firstParty: undefined,
			staleAllowUnmarkedClients: true,
			warn,
		});
		await authorize(app);
		expect(warn).not.toHaveBeenCalledWith(
			expect.anything(),
			"authorize_client_not_marked_first_party",
		);
	});

	it("refuses a client explicitly marked NOT first-party regardless of the stale flag", async () => {
		const app = await makeApp({ firstParty: false, staleAllowUnmarkedClients: true });
		expect(errorOf(await authorize(app))).toBe("unauthorized_client");
	});

	it("still admits a marked client when the stale flag is present", async () => {
		const app = await makeApp({ firstParty: true, staleAllowUnmarkedClients: true });
		expect(errorOf(await authorize(app))).not.toBe("unauthorized_client");
	});
});

/*
 * The same invariant, driven through the YAML loader and
 * `InMemoryClientRepository` a real deployment uses. The cases above stub a
 * `ClientRepository` with object literals, which pass even against a
 * repository whose schema cannot represent `firstParty`.
 * `entrySchemaConformance.test.mts` in core catches that class mechanically;
 * this exercises the file-backed shape end to end.
 */
describe("/authorize first-party invariant, through a file-backed registry", () => {
	let tmpDir: string;

	beforeEach(() => {
		tmpDir = mkdtempSync(join(tmpdir(), "first-party-yaml-"));
	});

	afterEach(() => {
		rmSync(tmpDir, { recursive: true, force: true });
	});

	/** Write a clients.yaml and boot the router on the repository it produces. */
	const makeFileBackedApp = async (clientsYaml: string) => {
		const yamlPath = join(tmpDir, "clients.yaml");
		writeFileSync(yamlPath, clientsYaml, "utf8");
		const clientRepository = new InMemoryClientRepository(loadYamlMap(yamlPath, ClientEntrySchema));

		const registry = new GrantRegistry();
		registry.register("authorization_code", alwaysGrant());

		const { router } = await createOAuthRouter(express, {
			loginEntry: createTestLoginEntry(),
			requirements: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
			registry,
			...routerInputsOf(makeConfig(false)),
			clientRepository,
			codeRepository: {
				createCode: async () =>
					codeRecord({
						code: "code-x",
						client_id: CLIENT_ID,
						redirect_uri: REDIRECT_URI,
					}),
				findByCode: async () => null,
				consumeByCode: async () => null,
				removeByCode: async () => {},
			} as CodeRepository,
			keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		});

		const app = express();
		app.use(express.json());
		app.use((req, _res, next) => {
			(req as unknown as { session: Record<string, unknown> }).session = {
				isAuthenticated: true,
				user: { id: "user-1" },
			};
			next();
		});
		app.use("/oauth", router);
		return app;
	};

	const yamlFor = (marking?: string): string =>
		[
			`${CLIENT_ID}:`,
			"  tokenEndpointAuthMethod: none",
			"  allowedRedirectUris:",
			`    - ${REDIRECT_URI}`,
			"  allowedScopes:",
			"    - read",
			...(marking === undefined ? [] : [`  ${marking}`]),
			"",
		].join(String.fromCharCode(10));

	it("admits a YAML-registered client marked first-party", async () => {
		const app = await makeFileBackedApp(yamlFor("firstParty: true"));
		expect(errorOf(await authorize(app))).not.toBe("unauthorized_client");
	});

	it("refuses a YAML-registered client that omits the marking", async () => {
		const app = await makeFileBackedApp(yamlFor());
		expect(errorOf(await authorize(app))).toBe("unauthorized_client");
	});

	it("refuses a YAML-registered client marked firstParty: false", async () => {
		const app = await makeFileBackedApp(yamlFor("firstParty: false"));
		expect(errorOf(await authorize(app))).toBe("unauthorized_client");
	});

	it("refuses to boot on a misspelled marking rather than silently ignoring it", async () => {
		// `.strict()` earning its keep: an operator who writes `frstParty: true`
		// and sees `/authorize` refuse would otherwise have no way to tell a
		// typo from a rule they misunderstood.
		const yamlPath = join(tmpDir, "clients.yaml");
		writeFileSync(yamlPath, yamlFor("frstParty: true"), "utf8");
		expect(() => loadYamlMap(yamlPath, ClientEntrySchema)).toThrow(/frstParty/);
	});
});
