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
	AttemptCounterClient,
	AttemptCounterConsumeInput,
	AttemptCounterConsumeReply,
} from "./clients/attempt-counter.mjs";
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
import type { RedisDurability } from "./clients/durability.mjs";
import type {
	ActivateFederationGrantInput,
	CreatePendingFederationGrantInput,
	FederationGrantHashFields,
	FederationGrantSnapshot,
	FederationGrantStoreClient,
	NameFederationGrantIntentInput,
	NoteFederationGrantRefreshFailureInput,
	RefundFederationGrantRotationInput,
	ReplaceFederationGrantCredentialsInput,
	RequireFederationGrantReauthorizationInput,
	RetireFederationGrantIntentInput,
	RevokeFederationGrantInput,
	TakeFederationGrantRotationInput,
} from "./clients/federation-grant.mjs";
import type {
	FederationGrantConsentAnswered,
	FederationGrantIntentAdmission,
	FederationGrantIntentStoreClient,
} from "./clients/federation-grant-intent.mjs";
import type {
	FederationTokenAttachInput,
	FederationTokenReadInput,
	FederationTokenRemoveIfInput,
	FederationTokenReplaceIfInput,
	FederationTokenStoreClient,
} from "./clients/federation-tokens.mjs";
import type {
	AcquireMfaSubjectLeaseInput,
	AcquireMfaSubjectLeaseReply,
	ApplyMfaSubjectRecoveryInput,
	ApplyMfaSubjectRecoveryReply,
	AuthorizeMfaSubjectRecoveryInput,
	AuthorizeMfaSubjectRecoveryReply,
	MfaFactorRecordUpdateInput,
	MfaFactorSetCreateIfInput,
	MfaFactorSetEmptyingWriteInput,
	MfaFactorSetRemoveIfInput,
	MfaFactorSetWriteInput,
	MfaFactorStoreClient,
	MfaFirstBindingRead,
	MfaRemovedTransaction,
	MfaSubjectKeys,
	MfaTransactionStoreClient,
	MfaTransactionUpdateInput,
	NoteMfaExemptSuccessInput,
	NoteMfaFirstBindingInput,
	NoteMfaFirstBindingReply,
	RaiseMfaRecoverySetFloorInput,
	RaiseMfaRecoverySetFloorReply,
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
	SessionLifecycleCloseInput,
	SessionLifecycleCompleteInput,
	SessionLifecycleJoinInput,
	SessionLifecycleKeys,
	SessionLifecycleOpenInput,
	SessionLifecycleStoreClient,
	SessionLifecycleWriteDeadline,
} from "./clients/session-lifecycle.mjs";
import type {
	AccessTokenDenylistClient,
	ChallengeStoreClient,
	CodeRepositoryClient,
	ReplaySeenSetClient,
} from "./clients/single-key-stores.mjs";
import type {
	SubjectRevocationClient,
	SubjectSessionIndexClient,
	SubjectSessionIndexMultiClient,
	UserSessionStoreClient,
} from "./clients/user-sessions.mjs";

export type {
	AccessTokenDenylistClient,
	AcquireMfaSubjectLeaseInput,
	AcquireMfaSubjectLeaseReply,
	ActivateFederationGrantInput,
	ApplyMfaSubjectRecoveryInput,
	ApplyMfaSubjectRecoveryReply,
	AttemptCounterClient,
	AttemptCounterConsumeInput,
	AttemptCounterConsumeReply,
	AuthorizeMfaSubjectRecoveryInput,
	AuthorizeMfaSubjectRecoveryReply,
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
	FederationTokenAttachInput,
	FederationTokenReadInput,
	FederationTokenRemoveIfInput,
	FederationTokenReplaceIfInput,
	FederationTokenStoreClient,
	GrantConsentInput,
	MfaFactorRecordUpdateInput,
	MfaFactorSetCreateIfInput,
	MfaFactorSetEmptyingWriteInput,
	MfaFactorSetRemoveIfInput,
	MfaFactorSetWriteInput,
	MfaFactorStoreClient,
	MfaFirstBindingRead,
	MfaRemovedTransaction,
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
	RaiseMfaRecoverySetFloorInput,
	RaiseMfaRecoverySetFloorReply,
	RateLimiterClient,
	RateLimitIncrement,
	RedisDurability,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
	RefundFederationGrantRotationInput,
	ReplaceFederationGrantCredentialsInput,
	ReplaySeenSetClient,
	RequireFederationGrantReauthorizationInput,
	ReserveMfaSubjectAttemptInput,
	ReserveMfaSubjectAttemptReply,
	RetireFederationGrantIntentInput,
	RevokeFederationGrantInput,
	SessionLifecycleCloseInput,
	SessionLifecycleCompleteInput,
	SessionLifecycleJoinInput,
	SessionLifecycleKeys,
	SessionLifecycleOpenInput,
	SessionLifecycleStoreClient,
	SessionLifecycleWriteDeadline,
	SubjectRevocationClient,
	SubjectSessionIndexClient,
	SubjectSessionIndexMultiClient,
	TakeFederationGrantRotationInput,
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
		readonly subjectSessionIndexClient?: SubjectSessionIndexClient;
		readonly subjectRevocationClient?: SubjectRevocationClient;
		readonly federationTokenStoreClient?: FederationTokenStoreClient;
		readonly sessionLifecycleStoreClient?: SessionLifecycleStoreClient;
		readonly rateLimiterClient?: RateLimiterClient;
		readonly attemptCounterClient?: AttemptCounterClient;
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
