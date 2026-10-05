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
 * The one reading of a `core.federations` entry of type `github`: the keys it
 * carries beside the ones core owns (`enabled`, `type`, `trustUpstreamAmr`,
 * `callbackMeetsFreshness`, `callbackURL`), as a strict, flat schema. A key
 * written `null` reads as absent, and an absent key stays absent: what it means — GitHub's own logout,
 * no `redirect_to` accepted — is the provider's and the redirect policy's
 * reading, never a default filled in here.
 */

import { z } from "zod";

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** `value` without its keys written `null`; anything but an object is left as written. */
const withoutNulls = (value: unknown): unknown =>
	isRecord(value)
		? Object.fromEntries(Object.entries(value).filter(([, inner]) => inner !== null))
		: value;

const REQUIRED = "is required (a non-empty string)";
const required = z.string({ error: REQUIRED }).min(1, { error: REQUIRED });
const text = z.string({ error: "must be a string" });
const strings = z.array(text, { error: "must be a list of strings" });

const entryKeys = z.strictObject({
	clientId: required,
	clientSecret: required,
	redirectAllowlist: strings.optional(),
	sessionDomain: text.optional(),
	authCallbackUrl: text.optional(),
	clientUrl: text.optional(),
	endSessionEndpoint: text.optional(),
});

/**
 * The schema of a `github` entry's own keys: strict (a key it does not name
 * refuses the entry) and flat. A refusal names the key, never its value.
 */
export const githubEntrySchema = z.preprocess(withoutNulls, entryKeys);

/** A `github` entry's own keys, as {@link githubEntrySchema} answers them. */
export type GithubEntry = z.output<typeof githubEntrySchema>;
