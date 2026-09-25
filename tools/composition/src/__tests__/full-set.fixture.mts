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
 * The full set: the standalone template's composition (its fixture,
 * `all-modules-composition.fixture.mts`, imported whole) with every workspace
 * package the template does not depend on added the way a deployment adds
 * them to that manifest — the device grant, DPoP, mTLS, token exchange,
 * WebAuthn, and the Apple and GitHub federations.
 *
 * What the template's fixture substitutes, this one inherits. What it adds:
 *
 * - The four packages' `reference.conf` files, layered above core's as a
 *   deployment layers them, and the settings with no default laid over the
 *   resolved config (each feature's switch, the WebAuthn relying party, the
 *   two federation sections).
 * - The small modules each package's README has a deployment write: the
 *   WebAuthn, Apple and GitHub config bridges and a `grantPolicy` (WebAuthn
 *   refuses to boot without one, and no package ships one). The federation
 *   bridges add each adapter's `fetch`, pointed at a fake upstream: core's
 *   fake OpenID Provider for Apple, the GitHub package's fake GitHub.
 * - mTLS runs in-process on its `header` source from a loopback peer — the
 *   shape a TLS-terminating proxy in front of the provider gives it — with the
 *   mTLS package's test certificate.
 */

import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import {
	type AppConfig,
	createMemoryWebAuthnCredentialStore,
	defaultChallengeCeremonyModule,
	defineModule,
	type GrantPolicyHook,
	type Module,
	memoryChallengeStoreModule,
	memoryDeviceCodeStoreModule,
	memoryWebAuthnCredentialStoreModule,
} from "@o3co/auth-provider-core";
import { createFakeIdp, type FakeIdp } from "@o3co/auth-provider-core/testing";
import { DEVICE_CODE_GRANT_TYPE, deviceGrantModule } from "@o3co/auth-provider-device-grant";
import { dpopModule } from "@o3co/auth-provider-dpop";
import { appleFederationModule } from "@o3co/auth-provider-federation-apple";
import { githubFederationModule } from "@o3co/auth-provider-federation-github";
import { mtlsModule } from "@o3co/auth-provider-mtls";
import {
	TOKEN_EXCHANGE_GRANT_TYPE,
	tokenExchangeModule,
} from "@o3co/auth-provider-oauth-token-exchange";
import { redisChallengeStoreModule, redisDeviceCodeStoreModule } from "@o3co/auth-provider-redis";
import {
	type ComposeOptions,
	type Composition,
	compose,
	ISSUER,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { webauthnConfigSchema, webauthnModule } from "@o3co/auth-provider-webauthn";
import {
	createFakeGithub,
	type FakeGithub,
} from "../../../../packages/federation-github/src/__tests__/fake-github.mts";

const require = createRequire(import.meta.url);

/** Each added package's shipped defaults, as a deployment layers them. */
const REFERENCE_CONFS = [
	"@o3co/auth-provider-device-grant/reference.conf",
	"@o3co/auth-provider-dpop/reference.conf",
	"@o3co/auth-provider-mtls/reference.conf",
	"@o3co/auth-provider-webauthn/reference.conf",
].map((specifier) => require.resolve(specifier));

/** The mTLS package's self-signed client certificate. */
export const CLIENT_CERTIFICATE = readFileSync(
	new URL("../../../../packages/mtls/src/__tests__/fixtures/leaf.pem", import.meta.url),
	"utf8",
);

export const APPLE_LANDING = "https://app.test/apple";
export const GITHUB_LANDING = "https://app.test/github";

// ---------------------------------------------------------------------------
// Switches
// ---------------------------------------------------------------------------

/**
 * What the full set turns on beyond the template's own switches. Each is the
 * switch a deployment flips: a config key where the package has one, the
 * module's presence where it does not (token exchange, WebAuthn).
 */
export interface Features {
	readonly deviceGrant: boolean;
	readonly dpop: boolean;
	readonly mtls: boolean;
	readonly tokenExchange: boolean;
	readonly webauthn: boolean;
	readonly apple: boolean;
	readonly github: boolean;
}

export const ALL_ON: Features = {
	deviceGrant: true,
	dpop: true,
	mtls: true,
	tokenExchange: true,
	webauthn: true,
	apple: true,
	github: true,
};

/** Which store backs each added feature: memory on one replica, Redis on several. */
export type Stores = "memory" | "redis";

/** The settings with no default, laid over the resolved config for `features`. */
function withFeatures(config: AppConfig, features: Features): AppConfig {
	const c = config as unknown as {
		oauth: Record<string, Record<string, unknown>>;
		federations: Record<string, Record<string, unknown>>;
		webauthn?: Record<string, unknown>;
	};
	return {
		...config,
		oauth: {
			...c.oauth,
			deviceAuthorization: {
				...c.oauth.deviceAuthorization,
				enabled: features.deviceGrant,
				"verification-uri": `${ISSUER}/device`,
			},
			dpop: { ...c.oauth.dpop, enabled: features.dpop },
			mtls: {
				...c.oauth.mtls,
				enabled: features.mtls,
				source: "header",
				"cert-header": "x-forwarded-client-cert",
				"cert-header-dialect": "plain-pem",
				// supertest dials loopback, which the app sees as the forwarding hop.
				"trusted-proxies": ["loopback"],
				mode: "self-signed",
			},
		},
		webauthn: {
			...c.webauthn,
			rpId: "auth.test",
			rpName: "Composition",
			origin: [ISSUER],
		},
		federations: {
			...c.federations,
			apple: {
				enabled: features.apple,
				type: "apple",
				clientId: "com.example.composition",
				clientSecret: "apple-static-client-secret",
				callbackURL: `${ISSUER}/session/oauth/federation/apple/callback`,
				clientUrl: APPLE_LANDING,
			},
			github: {
				enabled: features.github,
				type: "github",
				clientId: "github-client",
				clientSecret: "github-secret",
				callbackURL: `${ISSUER}/session/oauth/federation/github/callback`,
				clientUrl: GITHUB_LANDING,
			},
		},
	} as unknown as AppConfig;
}

// ---------------------------------------------------------------------------
// The modules a deployment writes
// ---------------------------------------------------------------------------

/** The README's WebAuthn bootstrap: the `webauthn` section, through the package's schema. */
const webauthnConfigModule = defineModule({
	name: "deployment:webauthn-config",
	requires: ["config"] as const,
	provides: {
		webauthnConfig: ({ config }) =>
			webauthnConfigSchema.parse((config as unknown as { webauthn: unknown }).webauthn),
	},
});

/**
 * The deployment's grant policy. WebAuthn's grant refuses to boot without one
 * and no package ships one; this one allows what each grant allows by itself,
 * so every flow below is the grant's own answer.
 */
const grantPolicyModule = defineModule({
	name: "deployment:grant-policy",
	provides: {
		grantPolicy: (): GrantPolicyHook => ({
			kind: "deployment-allow",
			evaluate: async () => ({ outcome: "allow" }) as const,
		}),
	},
});

/**
 * Stands in for the deployment's own WebAuthn credential store on several
 * replicas: no package ships a shared one, and the README has a production
 * deployment wire its own database. Boot cannot tell it from a database, which
 * is the point — what `multi` refuses is the bundled memory module, by name.
 */
const deploymentCredentialStoreModule = defineModule({
	name: "deployment:webauthn-credential-store",
	provides: {
		webauthnCredentialStore: () => createMemoryWebAuthnCredentialStore(),
	},
});

export interface Fakes {
	readonly apple: FakeIdp;
	readonly github: FakeGithub;
}

let fakes: Promise<Fakes> | undefined;

/** The Apple and GitHub fakes, made once per test file and shared by every boot. */
export function sharedFakes(): Promise<Fakes> {
	fakes ??= (async () => ({
		// Apple's endpoints are fixed in the adapter, not discovered.
		apple: await createFakeIdp({
			issuer: "https://appleid.apple.com",
			authorizationEndpoint: "https://appleid.apple.com/auth/authorize",
			tokenEndpoint: "https://appleid.apple.com/auth/token",
			jwksUri: "https://appleid.apple.com/auth/keys",
			clientId: "com.example.composition",
			sub: APPLE_SUB,
		}),
		github: createFakeGithub(),
	}))();
	return fakes;
}

/** The subjects the Apple and GitHub fakes sign in, as the Store has them linked. */
const APPLE_SUB = "000123.apple-composition.0456";
const GITHUB_ID = 12345;

/** A federation section's fields, as the bridges read them (they check nothing else). */
const section = (config: AppConfig, name: string): Record<string, string> =>
	(config.federations as Record<string, Record<string, string>>)[name] ?? {};

function federationBridges(config: AppConfig, features: Features, f: Fakes): Module[] {
	const bridge = (name: "apple" | "github", fetch: typeof globalThis.fetch) => {
		const { clientId, clientSecret, callbackURL, clientUrl } = section(config, name);
		return defineModule({
			name: `deployment:${name}-federation-config`,
			provides: {
				[`${name}FederationConfig`]: () => ({
					clientId,
					clientSecret,
					callbackURL,
					clientUrl,
					fetch,
				}),
			},
		});
	};
	return [
		...(features.apple ? [appleFederationModule, bridge("apple", f.apple.fetch)] : []),
		...(features.github ? [githubFederationModule, bridge("github", f.github.fetch)] : []),
	];
}

/** The store behind each added feature that keeps state. */
interface AddedStores {
	readonly deviceCode: Stores;
	readonly challenge: Stores;
	readonly credential: Module;
}

/** Every module the template does not compose, as a deployment adds them to its manifest. */
function addedModules(
	config: AppConfig,
	features: Features,
	stores: AddedStores,
	f: Fakes,
): Module[] {
	return [
		deviceGrantModule({ config }),
		stores.deviceCode === "redis" ? redisDeviceCodeStoreModule : memoryDeviceCodeStoreModule,
		dpopModule,
		mtlsModule,
		...(features.tokenExchange ? [tokenExchangeModule] : []),
		...(features.webauthn
			? [
					webauthnModule,
					webauthnConfigModule,
					stores.credential,
					stores.challenge === "redis" ? redisChallengeStoreModule : memoryChallengeStoreModule,
					defaultChallengeCeremonyModule,
				]
			: []),
		grantPolicyModule,
		...federationBridges(config, features, f),
	];
}

// ---------------------------------------------------------------------------
// Registrations
// ---------------------------------------------------------------------------

export const TV = { id: "tv" } as const;
export const GATEWAY = { id: "gateway", secret: "gateway-secret" } as const;
export const BINDER = { id: "binder", secret: "binder-secret" } as const;

const EXTRA_CLIENTS: Readonly<Record<string, Record<string, unknown>>> = {
	// A public device client.
	[TV.id]: {
		tokenEndpointAuthMethod: "none",
		allowedScopes: ["openid"],
		defaultScopes: ["openid"],
		allowedGrantTypes: [DEVICE_CODE_GRANT_TYPE],
	},
	// A confidential client exchanging the web client's tokens for its own.
	[GATEWAY.id]: {
		tokenEndpointAuthMethod: "client_secret_basic",
		clientSecret: GATEWAY.secret,
		allowedScopes: ["openid", "profile"],
		allowedAudiences: [ISSUER],
		allowedGrantTypes: [TOKEN_EXCHANGE_GRANT_TYPE],
	},
	// A machine client whose tokens are sender-constrained by DPoP or mTLS.
	[BINDER.id]: {
		tokenEndpointAuthMethod: "client_secret_basic",
		clientSecret: BINDER.secret,
		allowedScopes: ["api.read"],
		defaultScopes: ["api.read"],
		allowedGrantTypes: ["client_credentials"],
	},
};

const EXTRA_USERS: Readonly<Record<string, Record<string, unknown>>> = {
	carol: { id: "u-carol", password: "carol-password-long", token: `apple:${APPLE_SUB}` },
	dave: { id: "u-dave", password: "dave-password-long", token: `github:${GITHUB_ID}` },
};

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

export interface FullSetOptions extends Omit<ComposeOptions, "extraModules" | "referenceConfs"> {
	readonly features?: Partial<Features>;
	/** The added features' stores: memory (the default), or Redis on the template's shared socket. */
	readonly stores?: Stores;
	/** One store's adapter against the rest (a replica-safety case). */
	readonly deviceCodeStore?: Stores;
	readonly challengeStore?: Stores;
	/**
	 * The WebAuthn credential store module. Default: core's memory module on
	 * memory stores, the deployment's own on Redis (no package ships a shared
	 * one).
	 */
	readonly credentialStore?: Module;
	/** Adjust the resolved config after the features are laid over it. */
	readonly adjust?: (config: AppConfig) => AppConfig;
}

export interface FullSet extends Composition {
	readonly fakes: Fakes;
}

/** The template's composition options for the full set. */
export async function fullSetOptions(options: FullSetOptions = {}): Promise<ComposeOptions> {
	const features = { ...ALL_ON, ...options.features };
	const stores = options.stores ?? "memory";
	const f = await sharedFakes();
	const added: AddedStores = {
		deviceCode: options.deviceCodeStore ?? stores,
		challenge: options.challengeStore ?? stores,
		credential:
			options.credentialStore ??
			(stores === "redis" ? deploymentCredentialStoreModule : memoryWebAuthnCredentialStoreModule),
	};
	const {
		features: _features,
		stores: _stores,
		deviceCodeStore: _deviceCodeStore,
		challengeStore: _challengeStore,
		credentialStore: _credentialStore,
		adjust: _adjust,
		...compose
	} = options;
	return {
		...compose,
		referenceConfs: REFERENCE_CONFS,
		config: (resolved) => {
			const adjusted = options.config ? options.config(resolved) : resolved;
			const featured = withFeatures(adjusted, features);
			return options.adjust ? options.adjust(featured) : featured;
		},
		extraModules: (config) => addedModules(config, features, added, f),
		extraClients: { ...EXTRA_CLIENTS, ...options.extraClients },
		extraUsers: { ...EXTRA_USERS, ...options.extraUsers },
	};
}

/** Boots the full set: the template's composition, every other package added. */
export async function composeFullSet(options: FullSetOptions = {}): Promise<FullSet> {
	const composition = await compose(await fullSetOptions(options));
	return { ...composition, fakes: await sharedFakes() };
}

export { deploymentCredentialStoreModule, memoryWebAuthnCredentialStoreModule };

// ---------------------------------------------------------------------------
// Sender constraints
// ---------------------------------------------------------------------------

const dpopKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
const { kty, crv, x, y } = dpopKey.publicKey.export({ format: "jwk" });
export const DPOP_JWK = { kty, crv, x, y } as const;

const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");

/** An RFC 9449 proof for `htm` `htu`, signed ES256 under the one test key. */
export function dpopProof(htm: string, htu: string, claims: Record<string, unknown> = {}): string {
	const input = `${b64({ typ: "dpop+jwt", alg: "ES256", jwk: DPOP_JWK })}.${b64({
		htm,
		htu,
		iat: Math.floor(Date.now() / 1000),
		jti: randomUUID(),
		...claims,
	})}`;
	const signature = sign("sha256", Buffer.from(input), {
		key: dpopKey.privateKey,
		dsaEncoding: "ieee-p1363",
	});
	return `${input}.${signature.toString("base64url")}`;
}
