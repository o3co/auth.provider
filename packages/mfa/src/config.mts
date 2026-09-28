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
 * The `mfa` configuration this package reads (the MFA ADR's D11, D19, D20,
 * D22), and the refusals D20 gives the MFA configuration: `mfa.mode` is
 * core's; the rest of the section — which core's schema passes through — is
 * read here.
 *
 * - `mfa.encryptionKeys`, the key ring every factor's data is sealed under:
 *   each key canonical base64 of 32 bytes, the ring checked by core's sealing
 *   rule under the key it was read from (no empty ring, no duplicate id, every
 *   id within the rule), every refusal naming the entry by index and quoting
 *   neither a key nor an id. The published development sample key is refused
 *   by #473's rule: where the environment the configuration was selected by,
 *   or `NODE_ENV`, is `production` or `staging`, and under
 *   `deployment.mode = "multi"`.
 * - `mfa.factors.totp`: the parameters of a new enrollment (digits 6-8,
 *   period 15-120 s — the step-8 owner decision, the ADR stating no bounds
 *   for either — SHA1, SHA256 or SHA512), the window every verification
 *   allows (0-2, D22), and the issuer an authenticator app shows, defaulting
 *   to the host `oauth.jwt.issuer` names. Read on its own too, for the factor,
 *   which never holds a key.
 *
 * No default is written here: they live in `config/reference.conf` (ADR
 * 2026-04-30). A refusal is a `RangeError` whose message starts with the key.
 */

import {
	checkSealingKeyRing,
	coerceBooleanFromEnv,
	decodeSealingKey,
	SEALING_KEY_BYTES,
	type SealingKeyRing,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { TotpFactorSettings } from "./totp/factor.mjs";
import { TOTP_ALGORITHMS } from "./totp/rfc6238.mjs";

/**
 * A published key for development only — canonical base64 of 32 bytes, the
 * ASCII text `o3co:mfa:development-sample-key!` — which a development
 * configuration may carry in place of `MFA_ENCRYPTION_KEY` (D11). Everyone
 * holds it, so data sealed under it is sealed from nobody: the settings
 * refuse it wherever the configuration was selected as production or
 * staging, `NODE_ENV` is either, or `deployment.mode` is `"multi"`.
 */
export const MFA_DEVELOPMENT_SAMPLE_KEY = "bzNjbzptZmE6ZGV2ZWxvcG1lbnQtc2FtcGxlLWtleSE=";

const SECTION_MISSING =
	"is missing: layer @o3co/auth-provider-mfa/reference.conf beneath the composition's configuration";

const wholeNumber = (min: number, max: number, unit: string) => {
	const error = `must be a whole number from ${min} to ${max}${unit}`;
	return z.number({ error }).int({ error }).min(min, { error }).max(max, { error });
};

const ISSUER_RULE =
	"must be a non-empty name without a colon, which the otpauth label puts between the issuer and the account";

/** `mfa.factors.totp`: the TOTP factor's switch and parameters (D19). */
export const mfaTotpConfigSchema = z.object(
	{
		enabled: coerceBooleanFromEnv,
		algorithm: z.enum(TOTP_ALGORITHMS, {
			error: `must be one of ${TOTP_ALGORITHMS.map((name) => `"${name}"`).join(", ")}`,
		}),
		digits: wholeNumber(6, 8, ""),
		period: wholeNumber(15, 120, " seconds"),
		window: wholeNumber(0, 2, " steps"),
		issuer: z
			.string({ error: ISSUER_RULE })
			.min(1, { error: ISSUER_RULE })
			.refine((issuer) => !issuer.includes(":"), { error: ISSUER_RULE })
			.optional(),
	},
	{ error: SECTION_MISSING },
);

const RING_SHAPE = "must be a list of { id, key } entries";

const factorsSchema = z.object({ totp: mfaTotpConfigSchema }, { error: SECTION_MISSING });

/** The `mfa` section's keys this package reads: the key ring and the factors (D19). `mfa.mode` is core's. */
export const mfaConfigSchema = z.object(
	{
		encryptionKeys: z.array(
			z.object(
				{
					id: z.string({ error: "must be a string" }),
					key: z.string({ error: "must be canonical base64 of 32 bytes" }).optional(),
				},
				{ error: RING_SHAPE },
			),
			{ error: RING_SHAPE },
		),
		factors: factorsSchema,
	},
	{ error: SECTION_MISSING },
);

/** `mfa.factors.totp` as the factor and its module read it: the switch, the parameters, and the issuer resolved. */
export interface MfaTotpSettings extends TotpFactorSettings {
	readonly enabled: boolean;
}

/** What this package reads from the `mfa` section. */
export interface MfaSettings {
	/** The ring, in order: the first key seals, every key opens. */
	readonly encryptionKeys: SealingKeyRing;
	readonly totp: MfaTotpSettings;
}

/** What a composition root tells the settings that its configuration cannot (#473). */
export interface MfaSettingsOptions {
	/**
	 * The name the deployment selected its configuration by — the standalone
	 * passes `CONFIG_ENV || NODE_ENV`. Read beside `NODE_ENV`, which is always
	 * consulted, by the sample-key refusal.
	 */
	readonly environment?: string;
}

const RING = "mfa.encryptionKeys";
const PRODUCTION_ENVIRONMENTS: ReadonlySet<string> = new Set(["production", "staging"]);

interface ConfigShape {
	readonly mfa?: unknown;
	readonly oauth?: { readonly jwt?: { readonly issuer?: unknown } };
	readonly deployment?: { readonly mode?: unknown };
}

/** `path` under `prefix`, an array index in brackets. */
const pathOf = (prefix: string, path: readonly PropertyKey[]): string =>
	path.reduce<string>(
		(text, segment) =>
			typeof segment === "number" ? `${text}[${segment}]` : `${text}.${String(segment)}`,
		prefix,
	);

/** `value` parsed by `schema`, or a `RangeError` naming each key refused, under `prefix`. */
function parseSection<T>(schema: z.ZodType<T>, value: unknown, prefix: string): T {
	const result = schema.safeParse(value);
	if (result.success) return result.data;
	throw new RangeError(
		result.error.issues.map((issue) => `${pathOf(prefix, issue.path)} ${issue.message}`).join("; "),
	);
}

/** The host `oauth.jwt.issuer` names, which the TOTP issuer defaults to. */
function issuerHost(config: ConfigShape): string {
	const issuer = config.oauth?.jwt?.issuer;
	let host = "";
	if (typeof issuer === "string") {
		try {
			host = new URL(issuer).hostname;
		} catch {
			host = "";
		}
	}
	// A bracketed IPv6 host would carry the colon the label cannot.
	if (host === "" || host.includes(":")) {
		throw new RangeError(
			"mfa.factors.totp.issuer is not set, and oauth.jwt.issuer names no host it could default to: set MFA_TOTP_ISSUER",
		);
	}
	return host;
}

function totpSettings(
	totp: z.infer<typeof mfaTotpConfigSchema>,
	config: ConfigShape,
): MfaTotpSettings {
	return {
		enabled: totp.enabled,
		algorithm: totp.algorithm,
		digits: totp.digits,
		period: totp.period,
		window: totp.window,
		issuer: totp.issuer ?? issuerHost(config),
	};
}

/** `mfa.factors.totp`, read on its own — what the TOTP factor's module reads. A `RangeError` names each key refused. */
export function readMfaTotpSettings(config: unknown): MfaTotpSettings {
	const shape = (config ?? {}) as ConfigShape;
	const section = parseSection(
		z.object({ factors: factorsSchema }, { error: SECTION_MISSING }),
		shape.mfa,
		"mfa",
	);
	return totpSettings(section.factors.totp, shape);
}

/**
 * The sample key's refusal (#473's rule): the environment the configuration
 * was selected by, or `NODE_ENV`, is production or staging, or
 * `deployment.mode` is `"multi"`. Every key opens, so it is refused wherever
 * it sits in the ring.
 */
function refuseSampleKey(ring: SealingKeyRing, config: ConfigShape, options: MfaSettingsOptions) {
	const sample = decodeSealingKey(MFA_DEVELOPMENT_SAMPLE_KEY);
	const index = ring.findIndex((entry) => sample !== undefined && entry.key.equals(sample));
	if (index === -1) return;
	// Both names are consulted, each whatever its case and the whitespace
	// around it — "Production" or "production\n" names production as surely —
	// and the one that matched is the one reported, normalised.
	const productionEnvironment = [options.environment, process.env.NODE_ENV]
		.map((name) => (typeof name === "string" ? name.trim().toLowerCase() : undefined))
		.find((name): name is string => name !== undefined && PRODUCTION_ENVIRONMENTS.has(name));
	const reasons: string[] = [];
	if (productionEnvironment !== undefined) {
		reasons.push(`the environment is "${productionEnvironment}"`);
	}
	if (config.deployment?.mode === "multi") {
		reasons.push(
			'deployment.mode is "multi" (a multi-replica deployment is never a development box)',
		);
	}
	if (reasons.length === 0) return;
	throw new RangeError(
		`${RING}[${index}].key is the development sample key (MFA_DEVELOPMENT_SAMPLE_KEY), refused because ${reasons.join(" and ")}: set MFA_ENCRYPTION_KEY to a key of your own (openssl rand -base64 32)`,
	);
}

/** The ring the entries name, or a `RangeError` naming the entry refused and quoting none. */
function readKeyRing(
	entries: z.infer<typeof mfaConfigSchema>["encryptionKeys"],
	config: ConfigShape,
	options: MfaSettingsOptions,
): SealingKeyRing {
	if (entries.length === 0) {
		throw new RangeError(
			`${RING} is empty: set MFA_ENCRYPTION_KEY to a key of your own (openssl rand -base64 32)`,
		);
	}
	const ring = entries.map((entry, index) => {
		if (entry.key === undefined) {
			throw new RangeError(
				`${RING}[${index}].key is not set${index === 0 ? ": set MFA_ENCRYPTION_KEY, which feeds it (openssl rand -base64 32)" : ""}`,
			);
		}
		const key = decodeSealingKey(entry.key);
		if (key === undefined) {
			throw new RangeError(
				`${RING}[${index}].key must be canonical base64 of ${SEALING_KEY_BYTES} bytes`,
			);
		}
		return { id: entry.id, key };
	});
	checkSealingKeyRing(ring, RING);
	refuseSampleKey(ring, config, options);
	return ring;
}

/**
 * Everything this package reads from the `mfa` section: the key ring and the
 * TOTP factor's settings. `options.environment` is the name the composition
 * root selected its configuration by (#473). A refusal is a `RangeError` that
 * names the key and quotes no key material.
 */
export function readMfaSettings(config: unknown, options: MfaSettingsOptions = {}): MfaSettings {
	const shape = (config ?? {}) as ConfigShape;
	const section = parseSection(mfaConfigSchema, shape.mfa, "mfa");
	return {
		encryptionKeys: readKeyRing(section.encryptionKeys, shape, options),
		totp: totpSettings(section.factors.totp, shape),
	};
}
