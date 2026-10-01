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
 * `mfaResetModule`: the operator reset (`reset.mts`) as the `mfaReset`
 * component a Store reads after `createApp` returns
 * (`handle.components.mfaReset.resetMfaForSubject`).
 *
 * Installed beside `mfaModule`, apart from it: the reset ends every session
 * of the subject's, so it requires `subjectRevocationService` — a module of
 * its own — which the MFA routes do not. Requires the two MFA stores and the
 * configuration, whose `mfa.storeTimeoutMs` (`mfaModule`'s reference.conf)
 * bounds the lease the reset holds; reads `userRepository`, for the witness's
 * clear alone (`markMfaEnrolled`), `mailSender` (`requireEmailProof` needs
 * one), `auditSink` and `logger`. Eager, so its refusals are the boot's.
 */

import { defineModule, type ProviderDeps } from "@o3co/auth-provider-core";
import { mfaConfigSchema } from "./config.mjs";
import { checkFactorSetStoreTimeout } from "./factorSet.mjs";
import { createMfaReset, type MfaReset } from "./reset.mjs";

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/** The operator reset: `resetMfaForSubject`, from `@o3co/auth-provider-mfa`'s `mfaResetModule`. */
		readonly mfaReset?: MfaReset;
	}
}

const REQUIRES = [
	"config",
	"mfaFactorStore",
	"mfaTransactionStore",
	"subjectRevocationService",
] as const;
const OPTIONAL = ["userRepository", "mailSender", "auditSink", "logger"] as const;

type Requires = (typeof REQUIRES)[number];
type Optional = (typeof OPTIONAL)[number];

/** `mfa.storeTimeoutMs` as `mfaModule` reads it; a `RangeError` naming the key for one it would refuse, or none. */
function storeTimeoutOf(config: unknown): number {
	const given = (config as { mfa?: { storeTimeoutMs?: unknown } } | null | undefined)?.mfa
		?.storeTimeoutMs;
	const read = mfaConfigSchema.shape.storeTimeoutMs.safeParse(given);
	if (!read.success) {
		throw new RangeError(
			"mfa.storeTimeoutMs is not a whole number of milliseconds from 1000: mfaResetModule reads it from mfaModule's section — install mfaModule beside it",
		);
	}
	return checkFactorSetStoreTimeout(read.data);
}

/** The operator reset's module (see this file's header). */
export const mfaResetModule = defineModule<Requires, Optional>({
	name: "mfa-reset",
	requires: REQUIRES,
	optional: OPTIONAL,
	lifecycle: { mfaReset: { eager: true } },
	provides: {
		mfaReset: (deps: ProviderDeps<Requires, Optional>) =>
			createMfaReset({
				factorStore: deps.mfaFactorStore,
				transactionStore: deps.mfaTransactionStore,
				subjectRevocationService: deps.subjectRevocationService,
				...(deps.userRepository === undefined ? {} : { userRepository: deps.userRepository }),
				mailWired: deps.mailSender !== undefined,
				storeTimeoutMs: storeTimeoutOf(deps.config),
				...(deps.auditSink === undefined ? {} : { auditSink: deps.auditSink }),
				...(deps.logger === undefined ? {} : { logger: deps.logger }),
			}),
	},
});
