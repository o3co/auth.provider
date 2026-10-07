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
 * The configuration section of the module that keeps a subject's MFA factors
 * in the Store: `foundation-mfa-factor-store`, named after that module, its
 * four factor endpoints bound in the package's `config/reference.conf`
 * without a default.
 *
 * Guarantees: the schema refuses an unknown key and a URL that is not https
 * or loopback http, naming the key in printable characters and quoting no
 * value; a URL left out passes the schema — the reference binds each one to
 * a variable that may be unset — and {@link readFoundationMfaFactorStoreUrls}
 * refuses it. A module that reads the section provides its store eagerly
 * ({@link foundationMfaFactorStoreLifecycle}) and calls the reader first, so
 * a composition that installs it with any URL missing refuses the boot,
 * whether or not anything requires the store.
 */

import { auditErrorText, type ModuleSection } from "@o3co/auth-provider-core";
import { z } from "zod";
import { checkSecureEndpoint, describeEndpointRejection } from "../endpointUrl.mjs";

/** The section's name: the module's. */
export const FOUNDATION_MFA_FACTOR_STORE_SECTION = "foundation-mfa-factor-store";

/** The four endpoints, in the order a refusal names them. */
const URL_KEYS = ["listUrl", "createUrl", "updateUrl", "deleteUrl"] as const;

/** Each key's variable, named after its path. */
const VARIABLES: Readonly<Record<(typeof URL_KEYS)[number], string>> = {
	listUrl: "FOUNDATION_MFA_FACTOR_STORE_LIST_URL",
	createUrl: "FOUNDATION_MFA_FACTOR_STORE_CREATE_URL",
	updateUrl: "FOUNDATION_MFA_FACTOR_STORE_UPDATE_URL",
	deleteUrl: "FOUNDATION_MFA_FACTOR_STORE_DELETE_URL",
};

const SECTION_MISSING =
	"is missing: layer @o3co/auth-provider-foundation/reference.conf beneath the composition's configuration";

/** A Store endpoint, when present: the rule the user repository holds its URLs to. */
const storeUrl = z
	.string({ error: "must be a string" })
	.superRefine((value, ctx) => {
		const rejection = checkSecureEndpoint(value);
		if (rejection !== null) {
			ctx.addIssue({ code: "custom", message: describeEndpointRejection(rejection) });
		}
	})
	.optional();

/** The section: the four URLs, each optional here, and no other key. */
const schema = z.strictObject(
	{
		listUrl: storeUrl,
		createUrl: storeUrl,
		updateUrl: storeUrl,
		deleteUrl: storeUrl,
	},
	{
		error: (issue) => {
			if (issue.code === "unrecognized_keys") {
				return `has a key it does not know: ${issue.keys.map((key) => `"${auditErrorText(key)}"`).join(", ")}`;
			}
			return issue.input === undefined ? SECTION_MISSING : "must be a section of keys";
		},
	},
);

/** The section as the module declares it: its schema, and the package's reference. */
export const foundationMfaFactorStoreSection = {
	schema,
	reference: new URL("../../config/reference.conf", import.meta.url),
} as const satisfies ModuleSection<typeof schema>;

/**
 * The lifecycle of a module that reads the section: its store is built at
 * boot whether or not anything requires it, so the reader always runs.
 */
export const foundationMfaFactorStoreLifecycle = {
	mfaFactorStore: { eager: true },
} as const;

/** The section as its schema reads it. */
export type FoundationMfaFactorStoreSection = z.output<typeof schema>;

/** The Store's four MFA factor endpoints. */
export interface FoundationMfaFactorStoreUrls {
	readonly listUrl: string;
	readonly createUrl: string;
	readonly updateUrl: string;
	readonly deleteUrl: string;
}

/**
 * The four URLs of a parsed section, or a `RangeError` naming each one
 * missing by its path and its variable.
 */
export function readFoundationMfaFactorStoreUrls(
	section: FoundationMfaFactorStoreSection,
): FoundationMfaFactorStoreUrls {
	const missing = URL_KEYS.filter((key) => section[key] === undefined);
	if (missing.length > 0) {
		throw new RangeError(
			`${missing
				.map((key) => `${FOUNDATION_MFA_FACTOR_STORE_SECTION}.${key} (${VARIABLES[key]})`)
				.join(", ")} must be set: the Store keeps the MFA factors only with all four endpoints`,
		);
	}
	return {
		listUrl: section.listUrl as string,
		createUrl: section.createUrl as string,
		updateUrl: section.updateUrl as string,
		deleteUrl: section.deleteUrl as string,
	};
}
