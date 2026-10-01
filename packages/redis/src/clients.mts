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
 * The per-purpose backing-client contracts the Redis adapters in this package consume, in
 * Redis-command terms (see README, "Backing-client contract"), one file per store family under
 * `./clients/`, and the ComponentMap slot each fills.
 */

import type {
	ConsentRecordFields,
	ConsentStoreClient,
	GrantConsentInput,
	ParkPendingConsentInput,
	PendingConsentKeyspace,
	PendingConsentStoreClient,
} from "./clients/consent.mjs";
import type {
	CreateDeviceCodeRecordInput,
	DeviceCodeDecisionInput,
	DeviceCodeDecisionReply,
	DeviceCodeKeyspace,
	DeviceCodePollReply,
	DeviceCodeRecordFields,
	DeviceCodeStoreClient,
} from "./clients/device-code.mjs";
import type {
	ActivateFederationGrantInput,
	CreatePendingFederationGrantInput,
	FederationGrantHashFields,
	FederationGrantSnapshot,
	FederationGrantStoreClient,
	NameFederationGrantIntentInput,
	NoteFederationGrantRefreshFailureInput,
	ReplaceFederationGrantCredentialsInput,
	RequireFederationGrantReauthorizationInput,
	RetireFederationGrantIntentInput,
	RevokeFederationGrantInput,
} from "./clients/federation-grant.mjs";
import type {
	FederationGrantConsentAnswered,
	FederationGrantIntentAdmission,
	FederationGrantIntentStoreClient,
} from "./clients/federation-grant-intent.mjs";
import type { FederationTokenStoreClient } from "./clients/federation-tokens.mjs";
import type {
	MfaFactorRecordUpdateInput,
	MfaFactorStoreClient,
	MfaFirstBindingRead,
	MfaSubjectKeys,
	MfaTransactionStoreClient,
	MfaTransactionUpdateInput,
	NoteMfaExemptSuccessInput,
	NoteMfaFirstBindingInput,
	NoteMfaFirstBindingReply,
	RedisDurability,
	ReserveMfaSubjectAttemptInput,
	ReserveMfaSubjectAttemptReply,
} from "./clients/mfa.mjs";
import type { RateLimiterClient, RateLimitIncrement } from "./clients/rate-limiter.mjs";
import type {
	DisposableRefreshTokenFamilyClient,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
} from "./clients/refresh-token-family.mjs";
import type {
	AccessTokenDenylistClient,
	ChallengeStoreClient,
	CodeRepositoryClient,
	ReplaySeenSetClient,
} from "./clients/single-key-stores.mjs";
import type {
	SessionFamilyIndexClient,
	SessionRPRegistryClient,
	SessionRPRegistryMultiClient,
	SessionSidSortedSetClient,
	SessionSidSortedSetMultiClient,
	SubjectRevocationClient,
	SubjectSessionIndexClient,
	SubjectSessionIndexMultiClient,
	UserSessionStoreClient,
} from "./clients/user-sessions.mjs";

export type {
	AccessTokenDenylistClient,
	ActivateFederationGrantInput,
	ChallengeStoreClient,
	CodeRepositoryClient,
	ConsentRecordFields,
	ConsentStoreClient,
	CreateDeviceCodeRecordInput,
	CreatePendingFederationGrantInput,
	DeviceCodeDecisionInput,
	DeviceCodeDecisionReply,
	DeviceCodeKeyspace,
	DeviceCodePollReply,
	DeviceCodeRecordFields,
	DeviceCodeStoreClient,
	DisposableRefreshTokenFamilyClient,
	FederationGrantConsentAnswered,
	FederationGrantHashFields,
	FederationGrantIntentAdmission,
	FederationGrantIntentStoreClient,
	FederationGrantSnapshot,
	FederationGrantStoreClient,
	FederationTokenStoreClient,
	GrantConsentInput,
	MfaFactorRecordUpdateInput,
	MfaFactorStoreClient,
	MfaFirstBindingRead,
	MfaSubjectKeys,
	MfaTransactionStoreClient,
	MfaTransactionUpdateInput,
	NameFederationGrantIntentInput,
	NoteFederationGrantRefreshFailureInput,
	NoteMfaExemptSuccessInput,
	NoteMfaFirstBindingInput,
	NoteMfaFirstBindingReply,
	ParkPendingConsentInput,
	PendingConsentKeyspace,
	PendingConsentStoreClient,
	RateLimiterClient,
	RateLimitIncrement,
	RedisDurability,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
	ReplaceFederationGrantCredentialsInput,
	ReplaySeenSetClient,
	RequireFederationGrantReauthorizationInput,
	ReserveMfaSubjectAttemptInput,
	ReserveMfaSubjectAttemptReply,
	RetireFederationGrantIntentInput,
	RevokeFederationGrantInput,
	SessionFamilyIndexClient,
	SessionRPRegistryClient,
	SessionRPRegistryMultiClient,
	SessionSidSortedSetClient,
	SessionSidSortedSetMultiClient,
	SubjectRevocationClient,
	SubjectSessionIndexClient,
	SubjectSessionIndexMultiClient,
	UserSessionStoreClient,
};

// ---------------------------------------------------------------------------
// ComponentMap augmentations: backing-client slots consumed by redis adapters,
// visible to any TypeScript consumer that imports from
// `@o3co/auth-provider-redis`.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly challengeStoreClient?: ChallengeStoreClient;
		readonly accessTokenDenylistClient?: AccessTokenDenylistClient;
		readonly replaySeenSetClient?: ReplaySeenSetClient;
		readonly refreshTokenFamilyClient?: RefreshTokenFamilyClient;
		readonly userSessionStoreClient?: UserSessionStoreClient;
		readonly sessionRPRegistryClient?: SessionRPRegistryClient;
		readonly sessionFamilyIndexClient?: SessionFamilyIndexClient;
		readonly sessionFederationIndexClient?: SessionSidSortedSetClient;
		readonly subjectSessionIndexClient?: SubjectSessionIndexClient;
		readonly subjectRevocationClient?: SubjectRevocationClient;
		readonly federationTokenStoreClient?: FederationTokenStoreClient;
		readonly rateLimiterClient?: RateLimiterClient;
		readonly codeRepositoryClient?: CodeRepositoryClient;
		readonly deviceCodeStoreClient?: DeviceCodeStoreClient;
		readonly consentStoreClient?: ConsentStoreClient;
		readonly pendingConsentStoreClient?: PendingConsentStoreClient;
		readonly federationGrantStoreClient?: FederationGrantStoreClient;
		readonly federationGrantIntentStoreClient?: FederationGrantIntentStoreClient;
		readonly mfaFactorStoreClient?: MfaFactorStoreClient;
		readonly mfaTransactionStoreClient?: MfaTransactionStoreClient;
	}
}
