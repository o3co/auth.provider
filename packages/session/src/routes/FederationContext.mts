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
 * What the federation stages share: the router's context, built once when the
 * router is, and the token type a stored upstream token record keeps. A stage
 * reads the context and never changes it.
 */

import type {
	Admission,
	AuditSink,
	FederationProvider,
	FederationTokenStore,
	Logger,
	SessionClaim,
	SessionFederationIndex,
	UserRepository,
} from "@o3co/auth-provider-core";
import type { SessionAdmissionAction } from "../admissionActions.mjs";
import type { FederationRedirectPolicy } from "../federations/redirect-policy.mjs";
import type { FederationTransactionCookie } from "./FederationTransactionCookie.mjs";

/** The router's options the stages read, and what the router derives from them once. */
export interface FederationRouterContext extends FederationTransactionCookie {
	readonly federationProviders: ReadonlyMap<string, FederationProvider>;
	readonly federationRedirectPolicyResolver: ReadonlyMap<string, FederationRedirectPolicy>;
	readonly providerCallbackUrls: ReadonlyMap<string, string>;
	readonly userRepository: UserRepository;
	readonly sessionFederationIndex: SessionFederationIndex;
	readonly federationTokenStore: FederationTokenStore;
	readonly federationTransactionTtlMs: number;
	readonly auditSink: AuditSink | undefined;
	readonly logger: Logger;
	/** The origins besides this one a link may be started from (`session.csrf.trustedOrigins`). */
	readonly linkTrustedOrigins: readonly string[];
	/** The link flow's one reading of a session: admission, with the router's slots. */
	readonly admitLink: (
		claim: SessionClaim,
		action: SessionAdmissionAction,
		log: Logger,
	) => Promise<Admission>;
}

/**
 * The record's `tokenType` for what an adapter answered: the upstream's
 * spelling verbatim, even when it is not a token type, because the
 * disclosing route reads only an absent field as `Bearer` — erasing an
 * unusable value would turn a refusal into a 200. A non-string is recorded
 * as `""`, which that route also refuses.
 */
export const recordedTokenType = (named: unknown): string | undefined => {
	if (named === undefined) return undefined;
	return typeof named === "string" ? named : "";
};
