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
 * The one reading of a `core.federations` entry of type `apple`: the keys it
 * carries beside the ones core owns (`enabled`, `type`, `trustUpstreamAmr`,
 * `callbackURL`), as a strict, flat schema. A key written `null` reads as
 * absent, and an absent key stays absent: what it means — no upstream logout
 * endpoint, no `redirect_to` accepted — is the provider's and the redirect
 * policy's reading, never a default filled in here. The provider's test seams
 * (`jwksUri`, `fetch`) are not entry keys: the type module's `fetch` option is
 * the seam.
 */

import { z } from "zod";

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** `value` without the keys written `null`. */
const withoutNulls = (value: unknown): unknown =>
	isRecord(value)
		? Object.fromEntries(Object.entries(value).filter(([, inner]) => inner !== null))
		: value;

const REQUIRED = "is required (a non-empty string)";
const required = z.string({ error: REQUIRED }).min(1, { error: REQUIRED });
const text = z.string({ error: "must be a string" });
const strings = z.array(text, { error: "must be a list of strings" });

/** The three keys that sign the client secret, together. */
const KEY_MATERIAL = ["teamId", "keyId", "privateKey"] as const;

const entryKeys = z.strictObject({
	clientId: required,
	clientSecret: required.optional(),
	teamId: required.optional(),
	keyId: required.optional(),
	privateKey: required.optional(),
	redirectAllowlist: strings.optional(),
	sessionDomain: text.optional(),
	authCallbackUrl: text.optional(),
	clientUrl: text.optional(),
	endSessionEndpoint: text.optional(),
});

/**
 * The schema of an `apple` entry's own keys: strict (a key it does not name
 * refuses the entry), flat, and with exactly one client-secret source — a
 * static `clientSecret`, or `teamId`, `keyId` and `privateKey` (the `.p8`
 * PEM) to sign one, all three.
 */
export const appleEntrySchema = z.preprocess(
	withoutNulls,
	entryKeys.superRefine((entry, ctx) => {
		const keyMaterial = KEY_MATERIAL.filter((key) => entry[key] !== undefined);
		if ((entry.clientSecret === undefined) === (keyMaterial.length === 0)) {
			ctx.addIssue({
				code: "custom",
				message:
					"must set exactly one of clientSecret (a static secret) or teamId, keyId and privateKey (to sign one)",
			});
			return;
		}
		if (keyMaterial.length === 0) return;
		for (const key of KEY_MATERIAL) {
			if (entry[key] !== undefined) continue;
			ctx.addIssue({
				code: "custom",
				path: [key],
				message: `is required with ${keyMaterial.join(" and ")}: teamId, keyId and privateKey sign the client secret together`,
			});
		}
	}),
);

/** An `apple` entry's own keys, as {@link appleEntrySchema} answers them. */
export type AppleEntry = z.output<typeof appleEntrySchema>;
