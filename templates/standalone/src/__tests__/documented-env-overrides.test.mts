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

import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	type AppConfig,
	createApp,
	type Module,
	moduleReferences,
	resolveAccessTokenLifetime,
} from "@o3co/auth-provider-core";
import { createFakeIdp, type FakeIdp } from "@o3co/auth-provider-core/testing";
import { googleFederationTypeModule } from "@o3co/auth-provider-federation-google";
import { oidcFederationTypeModule } from "@o3co/auth-provider-federation-oidc";
import { oauthEndpointsModule } from "@o3co/auth-provider-oauth";
import { sessionModule, sessionStoreModule } from "@o3co/auth-provider-session";
import { describe, expect, it } from "vitest";
import { buildModules } from "../buildModules.mjs";
import {
	expectedSessionRequirements,
	readOwnLayers,
	readSwitches,
	resolveConfigPaths,
	resolveForBoot,
	resolveLayers,
	type Switches,
} from "../configPath.mjs";
import { httpModule, keyStoreModule, templateReference } from "../modules.mjs";

/**
 * Boots the shipped config with EVERY documented override supplied the way an
 * operator supplies one: as a string.
 *
 * HOCON substitutes `${?VAR}` as a string, always. `app.mts` reads its own
 * switches with the template's schema and hands `createApp` what it resolved,
 * which boot parses once with plain Zod, so every schema leaf must read the
 * string itself. This suite reads through that path: `readSwitches` for what
 * is read before boot, `resolveForBoot` and `createApp` for the configuration
 * boot parsed.
 *
 * It is not a sample of interesting variables: `covers every documented
 * override` below fails when a `${?VAR}` is added to either config layer, or
 * documented in the README, without being exercised here.
 */

// config/ is two levels above this test file: src/__tests__/ → src/ → standalone/
const standaloneDir = fileURLToPath(new URL("../..", import.meta.url));
const configDir = fileURLToPath(new URL("../../config", import.meta.url));
const readmePath = fileURLToPath(new URL("../../README.md", import.meta.url));
const readmeJaPath = fileURLToPath(new URL("../../README.ja.md", import.meta.url));

/**
 * Every environment variable the shipped artifact documents, as the string an
 * operator would supply.
 *
 * `KEY_STORE_LOCAL_ALGORITHM` is `EdDSA` so the asymmetric key variables fit in the
 * same map: the HS256 branch of `signingKey.local` is a `.strict()`
 * discriminated-union member and refuses `privateKeyPath` and friends by
 * design. The HS256 shape gets its own test below.
 */
const DOCUMENTED_ENV: Readonly<Record<string, string>> = {
	// --- http ---------------------------------------------------------
	HTTP_PORT: "3000",
	HTTP_TRUST_PROXY: "10.0.0.0/8,loopback",
	HTTP_READINESS_TIMEOUT_MS: "1500",

	// --- logging ------------------------------------------------------
	LOGGING_LEVEL: "debug",

	// --- oauth.jwt ----------------------------------------------------
	OAUTH_JWT_ISSUER: "https://auth.test",
	KEY_STORE_PROVIDER: "local",
	KEY_STORE_LOCAL_ALGORITHM: "EdDSA",
	KEY_STORE_LOCAL_KID: "v1",
	KEY_STORE_LOCAL_SECRET: "documented-env-secret.at-least-32-bytes.ok",
	KEY_STORE_LOCAL_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nMC4=\n-----END PRIVATE KEY-----",
	KEY_STORE_LOCAL_PRIVATE_KEY_PATH: "./config/jwt-private.pem",
	KEY_STORE_LOCAL_PUBLIC_KEY: "-----BEGIN PUBLIC KEY-----\nMCo=\n-----END PUBLIC KEY-----",
	KEY_STORE_LOCAL_PUBLIC_KEY_PATH: "./config/jwt-public.pem",
	OAUTH_JWT_LEGACY_TYP_ACCEPT: "true",

	// --- oauth tokens / policy ----------------------------------------
	OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN: "900",
	OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN: "7200",
	// Deprecated alias of the default. Exported alongside the new variable on
	// purpose, with a different value: the new variable must win.
	OAUTH_ACCESS_TOKEN_EXPIRES_IN: "3600",
	OAUTH_REFRESH_TOKEN_EXPIRES_IN: "86400",
	OAUTH_OIDC_MODE: "dual",
	OAUTH_REVOCATION_ACCESS_TOKEN: "denylist",
	OAUTH_REVOCATION_SUBJECT: "unsupported",
	OAUTH_REQUIRE_EMAIL_VERIFIED: "true",
	OAUTH_REQUIRE_GRANT_TYPE_ALLOWLIST: "true",
	OAUTH_NONCE_MAX_LENGTH: "256",
	OAUTH_RESOURCE_INDICATOR_ENABLED: "true",
	OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ENABLED: "true",
	OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ALLOWED_SCOPES: "read, write",
	OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ALLOWED_AUDIENCES: "https://mcp.example",
	OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ALLOWED_HOSTS: "client.example, .trusted.example",
	OAUTH_CLIENT_ID_METADATA_DOCUMENTS_DENIED_HOSTS: "evil.example",
	OAUTH_CLIENT_ID_METADATA_DOCUMENTS_MAX_BYTES: "8192",
	OAUTH_CLIENT_ID_METADATA_DOCUMENTS_TIMEOUT_MS: "3000",
	OAUTH_CLIENT_ID_METADATA_DOCUMENTS_CACHE_MAX_AGE_MS: "60000",
	OAUTH_CLIENT_ID_METADATA_DOCUMENTS_MAX_CACHE_ENTRIES: "128",
	OAUTH_CLIENT_ID_METADATA_DOCUMENTS_STALE_IF_ERROR_MS: "120000",
	OAUTH_CLIENT_ID_METADATA_DOCUMENTS_NEGATIVE_CACHE_MS: "30000",
	OAUTH_CLIENT_ID_METADATA_DOCUMENTS_MAX_CONCURRENT_FETCHES: "4",
	CORE_TOKEN_BINDING_DISPATCH_POLICY: "intent-explicit",
	CORE_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS: "true",
	CORE_OUTBOUND_ALLOWED_HOSTS: "rp.example, .partner.example",
	CORE_OUTBOUND_DENIED_HOSTS: "blocked.example",
	CORE_OUTBOUND_INTERNAL_HOSTS: ".corp.internal",
	CORE_OUTBOUND_TIMEOUT_MS: "3000",
	CORE_OUTBOUND_MAX_RESPONSE_BYTES: "32768",
	CORE_OUTBOUND_EGRESS: "direct",

	// --- the grant switches ------------------------------------------
	OAUTH_SESSION_ENABLED: "false",
	OAUTH_AUTHORIZATION_GRANTS_AUTHORIZATION_CODE_ENABLED: "true",
	OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_ENABLED: "true",
	OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY: "reject",
	OAUTH_AUTHORIZATION_GRANTS_CLIENT_CREDENTIALS_ENABLED: "true",
	OAUTH_AUTHORIZATION_GRANTS_JWT_BEARER_ENABLED: "false",

	// --- session: the login routes -------------------------------------
	SESSION_CSRF_TTL_SECONDS: "7200",

	// --- session-store: the session cookie and its store ---------------
	SESSION_STORE_SECRET: "documented-env-session-secret.at-least-32-bytes.ok",
	SESSION_STORE_NAME: "auth.session",
	SESSION_STORE_MAX_AGE: "3600000",
	SESSION_STORE_SECURE: "false",
	SESSION_STORE_SAME_SITE: "lax",
	SESSION_STORE_DOMAIN: "auth.example.com",
	SESSION_STORE_STORAGE_TYPE: "redis",
	SESSION_STORE_STORAGE_REDIS_URL: "redis://redis:6379",
	SESSION_STORE_STORAGE_REDIS_PASSWORD: "session-store-password",

	// --- rate limiting ------------------------------------------------
	REDIS_RATE_LIMITER_FAIL_MODE: "open",
	CORE_RATE_LIMITER_MEMORY_MAX_BUCKETS: "10000",

	// --- adapters -----------------------------------------------------
	// Which adapter fills each slot: the composition root's own section,
	// read before the modules are chosen.
	ADAPTERS_RATE_LIMITER: "redis",
	ADAPTERS_ATTEMPT_COUNTER: "redis",
	ADAPTERS_USER_SESSION_STORES: "redis",
	ADAPTERS_ACCESS_TOKEN_DENYLIST: "redis",
	// The replay seen-set behind private_key_jwt client authentication.
	ADAPTERS_REPLAY_SEEN_SET: "redis",
	ADAPTERS_CONSENT_STORE: "redis",
	ADAPTERS_FEDERATION_TOKEN_STORE: "redis",
	ADAPTERS_FEDERATION_GRANT_STORE: "redis",
	ADAPTERS_FEDERATION_GRANT_INTENT_STORE: "redis",
	ADAPTERS_MFA_FACTOR_STORE: "redis",
	ADAPTERS_MFA_TRANSACTION_STORE: "redis",
	ADAPTERS_CODE_REPOSITORY: "redis",
	ADAPTERS_CLIENT_REPOSITORY: "yaml",
	ADAPTERS_USER_REPOSITORY: "yaml",
	// Selects the sink builder; "console" is the registered builtin. There
	// is deliberately no "none" — an unknown sink fails boot in buildModules
	// (pinned by audit-sink.test.mts), not in phase one, because the schema
	// keeps `adapters.auditSink` an open string so out-of-tree sinks need no
	// schema change here.
	ADAPTERS_AUDIT_SINK: "console",

	// --- JWKS ---------------------------------------------------------
	JWKS_PATH: "/keys/jwks.json",
	JWKS_CACHE_MAX_AGE: "600",

	// --- shared stores ------------------------------------------------
	CORE_DEPLOYMENT_MODE: "multi",
	// The consent stores' namespace.
	REDIS_CONSENT_STORE_KEY_PREFIX: "tenant-a:consent:",
	REDIS_ACCESS_TOKEN_DENYLIST_KEY_PREFIX: "atdeny:",
	REDIS_SESSION_STORES_KEY_PREFIX: "ss:",
	REDIS_REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX: "rtfam:",
	REDIS_REFRESH_TOKEN_FAMILY_STORE_CAS_RETRY_LIMIT: "3",
	REDIS_CLIENTS_URL: "redis://redis:6379",
	REDIS_CLIENTS_PASSWORD: "rt-family-password",
	// The federation token store's Redis branch.
	REDIS_FEDERATION_TOKEN_STORE_KEY_PREFIX: "ft:",
	REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_MODE: "required",
	REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
	// Federation grants: a user's standing consent that a client may obtain
	// upstream tokens without them. The overrides `reference.conf` declares.
	FEDERATION_GRANTS_ENABLED: "true",
	REDIS_FEDERATION_GRANT_STORE_ENCRYPTION_MODE: "required",
	FEDERATION_GRANTS_ALLOW_KEEP_ON_SUBJECT_REVOCATION: "false",
	// Acquisition's two deployment decisions — whether the callback
	// refuses an upstream account linked to another user, and the consent page.
	FEDERATION_GRANTS_IDENTITY_LOOKUP: "required",
	FEDERATION_GRANTS_CONSENT_URL: "/consent/grants",
	REDIS_FEDERATION_GRANT_STORE_KEY_PREFIX: "fg:",
	// The intent store's own namespace, which a deployment moves with the grant store's.
	REDIS_FEDERATION_GRANT_INTENT_STORE_KEY_PREFIX: "fg:",

	// --- multi-factor authentication ----------------------------------
	// The template's switch, `mfaMode`: off here, so the parse below
	// layers nothing of MFA. The rest is what the switch installs — the MFA
	// package's settings, foundation's Store-backed factor store's — and is
	// covered by the substitutions it brings (`liveSubstitutions`).
	MFA_MODE: "off",
	MFA_ENCRYPTION_KEY: "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=",
	MFA_PAGE_URL: "/mfa",
	MFA_STORE_TIMEOUT_MS: "5000",
	MFA_ENROLLMENT_REQUIRE_EMAIL_PROOF: "when-mail",
	MFA_TOTP_FACTOR_ENABLED: "true",
	MFA_TOTP_FACTOR_ALGORITHM: "SHA1",
	MFA_TOTP_FACTOR_DIGITS: "6",
	MFA_TOTP_FACTOR_PERIOD: "30",
	MFA_TOTP_FACTOR_WINDOW: "1",
	MFA_TOTP_FACTOR_ISSUER: "auth.test",
	MFA_RECOVERY_CODE_FACTOR_ENABLED: "true",
	MFA_RECOVERY_CODE_FACTOR_COUNT: "10",
	MFA_EMAIL_FACTOR_ENABLED: "false",
	MFA_EMAIL_FACTOR_ADDS_MFA: "false",
	MFA_EMAIL_FACTOR_CODE_TTL_SECONDS: "600",
	FOUNDATION_MFA_FACTOR_STORE_LIST_URL: "https://users.example.com/mfa/factors/list",
	FOUNDATION_MFA_FACTOR_STORE_CREATE_URL: "https://users.example.com/mfa/factors/create",
	FOUNDATION_MFA_FACTOR_STORE_UPDATE_URL: "https://users.example.com/mfa/factors/update",
	FOUNDATION_MFA_FACTOR_STORE_DELETE_URL: "https://users.example.com/mfa/factors/delete",

	// --- mail ---------------------------------------------------------
	// The SMTP sender's section, which the template installs outside
	// development and builds only where something sends.
	STANDARD_SMTP_MAIL_SENDER_HOST: "smtp.example.com",
	STANDARD_SMTP_MAIL_SENDER_PORT: "587",
	STANDARD_SMTP_MAIL_SENDER_SECURE: "starttls",
	STANDARD_SMTP_MAIL_SENDER_USER: "mailer",
	STANDARD_SMTP_MAIL_SENDER_PASSWORD: "mailer-password",
	STANDARD_SMTP_MAIL_SENDER_FROM: "auth@example.com",
	// …and the Redis stores' key namespaces, which the Redis package's two MFA
	// modules read.
	REDIS_MFA_FACTOR_STORE_KEY_PREFIX: "tenant-a:mfaf:",
	REDIS_MFA_TRANSACTION_STORE_KEY_PREFIX: "tenant-a:mfat:",

	// --- federation ---------------------------------------------------
	CORE_FEDERATIONS_GOOGLE_ENABLED: "true",
	CORE_FEDERATIONS_GOOGLE_CLIENT_ID: "google-client-id",
	CORE_FEDERATIONS_GOOGLE_CLIENT_SECRET: "google-client-secret",
	CORE_FEDERATIONS_GOOGLE_CALLBACK_URL:
		"https://auth.test/session/oauth/federation/google/callback",
	CORE_FEDERATIONS_GOOGLE_ACCESS_TYPE: "online",
	// The generic OIDC federation the template ships disabled.
	CORE_FEDERATIONS_OIDC_ENABLED: "true",
	CORE_FEDERATIONS_OIDC_ISSUER: "https://idp.test",
	CORE_FEDERATIONS_OIDC_CLIENT_ID: "oidc-client-id",
	CORE_FEDERATIONS_OIDC_CLIENT_SECRET: "oidc-client-secret",
	CORE_FEDERATIONS_OIDC_CALLBACK_URL: "https://auth.test/session/oauth/federation/oidc/callback",

	// --- repositories -------------------------------------------------
	REPOSITORIES_CLIENT_YAML_PATH: "./config/clients.yaml",
	REPOSITORIES_USER_YAML_PATH: "./config/users.yaml",
	REPOSITORIES_USER_HTTP_AUTHENTICATE_URL: "https://users.example.com/authenticate",
	REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL:
		"https://users.example.com/authenticate-by-token",
	REPOSITORIES_USER_HTTP_LINK_FEDERATED_IDENTITY_URL:
		"https://users.example.com/link-federated-identity",
	// The Store's identity lookup for federation grants (see ADR
	// 2026-09-17-federation-grants-offline-delegation).
	REPOSITORIES_USER_HTTP_FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL:
		"https://users.example.com/find-subject-by-federated-identity",
	// The Store's MFA enrollment witness endpoint (the MFA ADR's D12).
	REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL: "https://users.example.com/mfa/enrolled",
	REPOSITORIES_USER_HTTP_TIMEOUT: "5000",
	REPOSITORIES_USER_HTTP_MAX_RESPONSE_BYTES: "1048576",
	// The credential the http user adapter presents to the Store; >= 32 bytes.
	REPOSITORIES_USER_HTTP_BEARER_TOKEN:
		"0328d706529061d93abd6d826e09ef0f0a1e71a12af813b29e5cd2977b7dc63a",
	// The authorization-code repositories: the Redis one (selected above) and
	// the in-process one.
	REDIS_CODE_REPOSITORY_DEFAULT_EXPIRES_IN: "600",
	REDIS_CODE_REPOSITORY_KEY_PREFIX: "oauth:code:",
	STANDALONE_IN_MEMORY_CODE_REPOSITORY_DEFAULT_EXPIRES_IN: "600",

	// --- the login and consent pages ----------------------------------
	SESSION_LOGIN_PAGE_URL: "/login",
	OAUTH_CONSENT_PAGE_URL: "/consent",

	// --- cors ---------------------------------------------------------
	// A list, in the only shape an environment variable can carry one.
	// The schema splits and validates it; the `turns every non-boolean
	// override into its declared type` case below pins the result.
	HTTP_CORS_ALLOWED_ORIGINS: "https://app.example.com,http://localhost:5173",
};

/**
 * Substitutions that must NOT appear in `DOCUMENTED_ENV`, and why. Each one is
 * a variable whose documented behaviour is to *fail* boot, so setting it in
 * the all-overrides case would assert the opposite of the contract.
 */
const DELIBERATELY_UNSET: Readonly<Record<string, string>> = {
	OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS:
		"#330 tombstone — any value must fail boot with migration instructions",
	DEPLOYMENT_MODE:
		"renamed CORE_DEPLOYMENT_MODE, and only captured — set alone, or to another value, it fails boot",
	MEMORY_RATE_LIMITER_MAX_BUCKETS:
		"renamed CORE_RATE_LIMITER_MEMORY_MAX_BUCKETS, and only captured — set alone, or to another value, it fails boot",
	RATE_LIMIT_FAIL_MODE:
		"renamed REDIS_RATE_LIMITER_FAIL_MODE, and only captured — set alone, or to another value, it fails boot",
	REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX:
		"renamed REDIS_REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX, and only captured — set alone, or to another value, it fails boot",
	REFRESH_TOKEN_FAMILY_STORE_CAS_RETRY_LIMIT:
		"renamed REDIS_REFRESH_TOKEN_FAMILY_STORE_CAS_RETRY_LIMIT, and only captured — set alone, or to another value, it fails boot",
	FEDERATION_GRANTS_ENCRYPTION_MODE:
		"renamed REDIS_FEDERATION_GRANT_STORE_ENCRYPTION_MODE, and only captured — set alone, or to another value, it fails boot",
	OAUTH_TOKEN_BINDING_DISPATCH_POLICY:
		"renamed CORE_TOKEN_BINDING_DISPATCH_POLICY, and only captured — set alone, or to another value, it fails boot",
	OAUTH_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS:
		"renamed CORE_TOKEN_BINDING_BIND_CONFIDENTIAL_CLIENT_REFRESH_TOKENS, and only captured — set alone, or to another value, it fails boot",
	OAUTH_GRANTS_SESSION_ENABLED:
		"renamed OAUTH_SESSION_ENABLED, and only captured — set alone, or to another value, it fails boot",
	OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED:
		"renamed OAUTH_AUTHORIZATION_GRANTS_AUTHORIZATION_CODE_ENABLED, and only captured — set alone, or to another value, it fails boot",
	OAUTH_GRANTS_REFRESH_TOKEN_ENABLED:
		"renamed OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_ENABLED, and only captured — set alone, or to another value, it fails boot",
	OAUTH_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY:
		"renamed OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_UNKNOWN_FAMILY_POLICY, and only captured — set alone, or to another value, it fails boot",
	OAUTH_GRANTS_CLIENT_CREDENTIALS_ENABLED:
		"renamed OAUTH_AUTHORIZATION_GRANTS_CLIENT_CREDENTIALS_ENABLED, and only captured — set alone, or to another value, it fails boot",
	OAUTH_GRANTS_JWT_BEARER_ENABLED:
		"renamed OAUTH_AUTHORIZATION_GRANTS_JWT_BEARER_ENABLED, and only captured — set alone, or to another value, it fails boot",
	ENDPOINTS_CONSENT_URL:
		"renamed OAUTH_CONSENT_PAGE_URL, and only captured — set alone, or to another value, it fails boot",
	OAUTH_CIMD_ENABLED:
		"renamed OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ENABLED, and only captured — set alone, or to another value, it fails boot",
	OAUTH_CIMD_ALLOWED_SCOPES:
		"renamed OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ALLOWED_SCOPES, and only captured — set alone, or to another value, it fails boot",
	OAUTH_CIMD_ALLOWED_AUDIENCES:
		"renamed OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ALLOWED_AUDIENCES, and only captured — set alone, or to another value, it fails boot",
	OAUTH_CIMD_ALLOWED_HOSTS:
		"renamed OAUTH_CLIENT_ID_METADATA_DOCUMENTS_ALLOWED_HOSTS, and only captured — set alone, or to another value, it fails boot",
	OAUTH_CIMD_DENIED_HOSTS:
		"renamed OAUTH_CLIENT_ID_METADATA_DOCUMENTS_DENIED_HOSTS, and only captured — set alone, or to another value, it fails boot",
	OAUTH_CIMD_MAX_BYTES:
		"renamed OAUTH_CLIENT_ID_METADATA_DOCUMENTS_MAX_BYTES, and only captured — set alone, or to another value, it fails boot",
	OAUTH_CIMD_TIMEOUT_MS:
		"renamed OAUTH_CLIENT_ID_METADATA_DOCUMENTS_TIMEOUT_MS, and only captured — set alone, or to another value, it fails boot",
	OAUTH_CIMD_CACHE_MAX_AGE_MS:
		"renamed OAUTH_CLIENT_ID_METADATA_DOCUMENTS_CACHE_MAX_AGE_MS, and only captured — set alone, or to another value, it fails boot",
	OAUTH_CIMD_MAX_CACHE_ENTRIES:
		"renamed OAUTH_CLIENT_ID_METADATA_DOCUMENTS_MAX_CACHE_ENTRIES, and only captured — set alone, or to another value, it fails boot",
	OAUTH_CIMD_STALE_IF_ERROR_MS:
		"renamed OAUTH_CLIENT_ID_METADATA_DOCUMENTS_STALE_IF_ERROR_MS, and only captured — set alone, or to another value, it fails boot",
	OAUTH_CIMD_NEGATIVE_CACHE_MS:
		"renamed OAUTH_CLIENT_ID_METADATA_DOCUMENTS_NEGATIVE_CACHE_MS, and only captured — set alone, or to another value, it fails boot",
	OAUTH_CIMD_MAX_CONCURRENT_FETCHES:
		"renamed OAUTH_CLIENT_ID_METADATA_DOCUMENTS_MAX_CONCURRENT_FETCHES, and only captured — set alone, or to another value, it fails boot",
	OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256:
		"the authorization-code grant's pkce block was removed, and this is only captured — set at all, it fails boot",
	ENDPOINTS_LOGIN_URL:
		"renamed SESSION_LOGIN_PAGE_URL, and only captured — set alone, or to another value, it fails boot",
	SESSION_SECRET:
		"renamed SESSION_STORE_SECRET, and only captured — set alone, or to another value, it fails boot",
	SESSION_NAME:
		"renamed SESSION_STORE_NAME, and only captured — set alone, or to another value, it fails boot",
	SESSION_MAX_AGE:
		"renamed SESSION_STORE_MAX_AGE, and only captured — set alone, or to another value, it fails boot",
	SESSION_SECURE:
		"renamed SESSION_STORE_SECURE, and only captured — set alone, or to another value, it fails boot",
	SESSION_SAME_SITE:
		"renamed SESSION_STORE_SAME_SITE, and only captured — set alone, or to another value, it fails boot",
	SESSION_DOMAIN:
		"renamed SESSION_STORE_DOMAIN, and only captured — set alone, or to another value, it fails boot",
	SESSION_STORAGE_TYPE:
		"renamed SESSION_STORE_STORAGE_TYPE, and only captured — set alone, or to another value, it fails boot",
	SESSION_STORAGE_REDIS_URL:
		"renamed SESSION_STORE_STORAGE_REDIS_URL, and only captured — set alone, or to another value, it fails boot",
	SESSION_STORAGE_REDIS_PASSWORD:
		"renamed SESSION_STORE_STORAGE_REDIS_PASSWORD, and only captured — set alone, or to another value, it fails boot",
	LOG_LEVEL:
		"renamed LOGGING_LEVEL, and only captured — set alone, or to another value, it fails boot",
	CORS_ALLOWED_ORIGINS:
		"renamed HTTP_CORS_ALLOWED_ORIGINS, and only captured — set alone, or to another value, it fails boot",
	OAUTH_JWT_SIGNING_KEY_PROVIDER:
		"renamed KEY_STORE_PROVIDER, and only captured — set alone, or to another value, it fails boot",
	OAUTH_JWT_ALGORITHM:
		"renamed KEY_STORE_LOCAL_ALGORITHM, and only captured — set alone, or to another value, it fails boot",
	OAUTH_JWT_KID:
		"renamed KEY_STORE_LOCAL_KID, and only captured — set alone, or to another value, it fails boot",
	OAUTH_JWT_SECRET:
		"renamed KEY_STORE_LOCAL_SECRET, and only captured — set alone, or to another value, it fails boot",
	OAUTH_JWT_PRIVATE_KEY_PATH:
		"renamed KEY_STORE_LOCAL_PRIVATE_KEY_PATH, and only captured — set alone, or to another value, it fails boot",
	OAUTH_JWT_PUBLIC_KEY_PATH:
		"renamed KEY_STORE_LOCAL_PUBLIC_KEY_PATH, and only captured — set alone, or to another value, it fails boot",
	OAUTH_JWT_PRIVATE_KEY:
		"renamed KEY_STORE_LOCAL_PRIVATE_KEY, and only captured — set alone, or to another value, it fails boot",
	OAUTH_JWT_PUBLIC_KEY:
		"renamed KEY_STORE_LOCAL_PUBLIC_KEY, and only captured — set alone, or to another value, it fails boot",
	REFRESH_TOKEN_FAMILY_STORE_REDIS_URL:
		"renamed REDIS_CLIENTS_URL, and only captured — set alone, or to another value, it fails boot",
	REFRESH_TOKEN_FAMILY_STORE_REDIS_PASSWORD:
		"renamed REDIS_CLIENTS_PASSWORD, and only captured — set alone, or to another value, it fails boot",
	CLIENT_PATH:
		"renamed REPOSITORIES_CLIENT_YAML_PATH, and only captured — set alone, or to another value, it fails boot",
	CLIENT_USER_PATH:
		"renamed REPOSITORIES_USER_YAML_PATH, and only captured — set alone, or to another value, it fails boot",
	CLIENT_USER_AUTHENTICATE_URL:
		"renamed REPOSITORIES_USER_HTTP_AUTHENTICATE_URL, and only captured — set alone, or to another value, it fails boot",
	CLIENT_USER_AUTHENTICATE_BY_TOKEN_URL:
		"renamed REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL, and only captured — set alone, or to another value, it fails boot",
	CLIENT_USER_LINK_FEDERATED_IDENTITY_URL:
		"renamed REPOSITORIES_USER_HTTP_LINK_FEDERATED_IDENTITY_URL, and only captured — set alone, or to another value, it fails boot",
	CLIENT_USER_FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL:
		"renamed REPOSITORIES_USER_HTTP_FIND_SUBJECT_BY_FEDERATED_IDENTITY_URL, and only captured — set alone, or to another value, it fails boot",
	CLIENT_USER_BEARER_TOKEN:
		"renamed REPOSITORIES_USER_HTTP_BEARER_TOKEN, and only captured — set alone, or to another value, it fails boot",
	CLIENT_USER_TIMEOUT:
		"renamed REPOSITORIES_USER_HTTP_TIMEOUT, and only captured — set alone, or to another value, it fails boot",
	CLIENT_USER_MAX_RESPONSE_BYTES:
		"renamed REPOSITORIES_USER_HTTP_MAX_RESPONSE_BYTES, and only captured — set alone, or to another value, it fails boot",
	CLIENT_CODE_DEFAULT_EXPIRES_IN:
		"renamed REDIS_CODE_REPOSITORY_DEFAULT_EXPIRES_IN (the Redis code repository) and STANDALONE_IN_MEMORY_CODE_REPOSITORY_DEFAULT_EXPIRES_IN (the in-process one), and only captured — set alone, or to another value, it fails boot",
	CLIENT_CODE_KEY_PREFIX:
		"renamed REDIS_CODE_REPOSITORY_KEY_PREFIX, and only captured — set alone, or to another value, it fails boot",
	CLIENT_CODE_ENDPOINT_URI:
		"removed: the Redis code repository uses the shared redis-clients connection; only captured — set at all, it fails boot",
	CLIENT_CODE_PASSWORD:
		"removed: the Redis code repository uses the shared redis-clients connection; only captured — set at all, it fails boot",
	ENDPOINTS_MFA_URL:
		"renamed MFA_PAGE_URL, and only captured — set alone, or to another value, it fails boot where MFA is installed",
	MFA_TOTP_ENABLED:
		"renamed MFA_TOTP_FACTOR_ENABLED, and only captured — set alone, or to another value, it fails boot where MFA is installed",
	MFA_TOTP_ISSUER:
		"renamed MFA_TOTP_FACTOR_ISSUER, and only captured — set alone, or to another value, it fails boot where MFA is installed",
};

/**
 * The federation variables `config/application.conf` documents on lines it
 * ships commented out — a key an operator binds by uncommenting it — as the
 * string an operator would supply. They are not live substitutions, so they
 * are not in `DOCUMENTED_ENV`; the federation cases below bind them as their
 * comments write them (`commentedFederationBindings`).
 */
const COMMENTED_FEDERATION_ENV: Readonly<Record<string, string>> = {
	CORE_FEDERATIONS_GOOGLE_SESSION_DOMAIN: ".example.com",
	CORE_FEDERATIONS_GOOGLE_AUTH_CALLBACK_URL: "https://app.example.com/auth/callback",
	CORE_FEDERATIONS_GOOGLE_CLIENT_URL: "https://app.example.com/",
	CORE_FEDERATIONS_GOOGLE_REQUIRE_AUTHORIZATION_RESPONSE_ISS: "false",
};

/**
 * Each `# <key> = ${?CORE_FEDERATIONS_<NAME>_…}` line of the shipped
 * `config/application.conf`, uncommented as an operator's layer above it:
 * `core.federations.<name>.<key> = ${?…}`.
 */
function commentedFederationBindings(): string {
	const { applicationConfPath } = resolveConfigPaths(configDir, "production");
	return readFileSync(applicationConfPath, "utf8")
		.split("\n")
		.flatMap((line) => {
			const match =
				/^\s*#\s*([A-Za-z]+) = \$\{\?(CORE_FEDERATIONS_([A-Z0-9]+)_[A-Z0-9_]+)\}\s*$/.exec(line);
			if (match === null) return [];
			const [, key, variable, name] = match as unknown as [string, string, string, string];
			return [`core.federations.${name.toLowerCase()}.${key} = \${?${variable}}`];
		})
		.join("\n");
}

/**
 * The provider environment `o3co/auth`'s `tests/docker-compose.yml` sets,
 * transcribed: each renamed variable under its old and its new name, the two
 * at one value. The umbrella E2E boots the shipped template with exactly this,
 * so a parse failure here is a red umbrella build that this repository can see
 * first. `SESSION_STORE_SECURE=false` is the one it cannot run without: the
 * suite speaks plain HTTP.
 *
 * The two `FEDERATION_TOKEN_STORE` lines are required: the federation token
 * store defaults to memory, the standalone's memory module declares itself
 * replica-unsafe, and `CORE_DEPLOYMENT_MODE=multi` refuses it by name unless the
 * Redis store is selected with its encryption key.
 */
const UMBRELLA_E2E_ENV: Readonly<Record<string, string>> = {
	OAUTH_JWT_ALGORITHM: "HS256",
	KEY_STORE_LOCAL_ALGORITHM: "HS256",
	OAUTH_JWT_SECRET: "e2e-shared-hs256-secret.at-least-32-bytes.ok",
	KEY_STORE_LOCAL_SECRET: "e2e-shared-hs256-secret.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.e2e.test",
	SESSION_SECRET: "lO0QH09fuKSGuViZ9myJbH3jsgai99A2GpC3RYRuy6Y=",
	SESSION_STORE_SECRET: "lO0QH09fuKSGuViZ9myJbH3jsgai99A2GpC3RYRuy6Y=",
	SESSION_SECURE: "false",
	SESSION_STORE_SECURE: "false",
	SESSION_NAME: "auth.session",
	SESSION_STORE_NAME: "auth.session",
	DEPLOYMENT_MODE: "multi",
	CORE_DEPLOYMENT_MODE: "multi",
	REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: "redis://redis:6379",
	REDIS_CLIENTS_URL: "redis://redis:6379",
	SESSION_STORAGE_REDIS_URL: "redis://redis:6379",
	SESSION_STORE_STORAGE_REDIS_URL: "redis://redis:6379",
	USER_SESSION_STORES_ADAPTER: "redis",
	ADAPTERS_USER_SESSION_STORES: "redis",
	RATE_LIMITER_ADAPTER: "redis",
	ADAPTERS_RATE_LIMITER: "redis",
	OAUTH_CODE_ADAPTER: "redis",
	ADAPTERS_CODE_REPOSITORY: "redis",
	FEDERATION_TOKEN_STORE_TYPE: "redis",
	ADAPTERS_FEDERATION_TOKEN_STORE: "redis",
	REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
	CLIENT_USER_TYPE: "yaml",
	ADAPTERS_USER_REPOSITORY: "yaml",
	OAUTH_RESOURCE_INDICATOR_ENABLED: "true",
	OAUTH_REQUIRE_EMAIL_VERIFIED: "true",
	OAUTH_GRANTS_SESSION_ENABLED: "true",
	OAUTH_SESSION_ENABLED: "true",
	MFA_MODE: "off",
};

/** The template's own files for `configEnv`, under `operatorLayer` — HOCON an operator adds above them — when given. */
function ownFiles(configEnv: string, operatorLayer?: string): string[] {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, configEnv);
	if (operatorLayer === undefined) return [envConfPath, applicationConfPath];
	const file = join(mkdtempSync(join(tmpdir(), "documented-env-overrides-")), "operator.conf");
	writeFileSync(file, operatorLayer);
	return [file, envConfPath, applicationConfPath];
}

/** Phase one, as `app.mts` reads it: the switches. */
function readShippedSwitches(env: Record<string, string>, configEnv = "production"): Switches {
	return readSwitches(readOwnLayers(ownFiles(configEnv), { env }));
}

/**
 * The stores an enabled federation needs beside it, which boot refuses a
 * composition without. What they hold is not this suite's question.
 */
const FEDERATION_STORES = Object.fromEntries(
	[
		"userSessionStore",
		"sessionRPRegistry",
		"sessionFamilyIndex",
		"sessionFederationIndex",
		"federationTokenStore",
		"refreshTokenFamilyRevocation",
	].map((key) => [key, {}]),
);

/** What core handed a federation type for one entry: its callback, and its own keys as the type's schema parsed them. */
interface Dispatched {
	readonly callbackURL: string;
	readonly entry: Readonly<Record<string, unknown>>;
}

/** A federation type's declaration, as far as this suite reads it. */
interface TypeDeclaration {
	readonly factory: (deps: unknown, instance: { name: string } & Dispatched) => unknown;
}

/**
 * `module`, a federation type module, with each type's factory recording what
 * core handed it into `dispatched`, by the entry's name, before building the
 * provider as the module does. The schema, the parse and the provider are the
 * module's own.
 */
function recordingDispatch(module: Module, dispatched: Map<string, Dispatched>): Module {
	const contributes = module.contributes as {
		readonly federationTypes: Readonly<Record<string, TypeDeclaration>>;
	};
	const federationTypes = Object.fromEntries(
		Object.entries(contributes.federationTypes).map(([type, declaration]) => [
			type,
			{
				...declaration,
				factory: (deps: unknown, instance: { name: string } & Dispatched) => {
					dispatched.set(instance.name, {
						callbackURL: instance.callbackURL,
						entry: instance.entry,
					});
					return declaration.factory(deps, instance);
				},
			},
		]),
	);
	return { ...module, contributes: { ...contributes, federationTypes } } as Module;
}

/**
 * The upstream the documented OIDC federation's issuer names. Its type
 * discovers the issuer at boot, so the module is handed this fake's `fetch`
 * rather than the network. Made once per file.
 */
let oidcUpstream: Promise<FakeIdp> | undefined;
const documentedOidcUpstream = (): Promise<FakeIdp> => {
	oidcUpstream ??= createFakeIdp({
		issuer: DOCUMENTED_ENV.CORE_FEDERATIONS_OIDC_ISSUER as string,
		discovery: true,
		clientId: DOCUMENTED_ENV.CORE_FEDERATIONS_OIDC_CLIENT_ID as string,
	});
	return oidcUpstream;
};

/**
 * The shipped layers under `env`, as `app.mts` hands them to boot, booted
 * with the federation types the template bundles: phase one for what the
 * composition expects of session admission, phase two resolved over the
 * reference of every package the template's modules come from (the
 * template's own and core's) and parsed once by `createApp` — no bridge on
 * the way. Core dispatches each enabled federation to its type, which parses
 * the entry with its own schema; `dispatched` is what each type was handed.
 * No other module is loaded unless `modules` names one: the parse is what this
 * suite asks about, and each key it reads is one core's schema declares, or
 * the section of a module it loads.
 */
async function bootDispatched(
	env: Record<string, string>,
	configEnv = "production",
	operatorLayer?: string,
	modules: readonly Module[] = [],
): Promise<{ readonly parsed: AppConfig; readonly dispatched: ReadonlyMap<string, Dispatched> }> {
	const own = readOwnLayers(ownFiles(configEnv, operatorLayer), { env });
	const switches = readSwitches(own);
	const dispatched = new Map<string, Dispatched>();
	const upstream = await documentedOidcUpstream();
	const handle = await createApp({
		modules: [
			recordingDispatch(googleFederationTypeModule(), dispatched),
			recordingDispatch(oidcFederationTypeModule({ fetch: upstream.fetch }), dispatched),
			...modules,
		],
		bootstrapComponents: {
			config: resolveForBoot(own, buildModules(switches, { environment: configEnv }), switches),
			pathResolver: (s: string) => s,
			...FEDERATION_STORES,
		} as never,
	});
	const parsed = handle.components.config;
	await handle.dispose();
	if (parsed === undefined) throw new Error("createApp booted without the parsed configuration");
	return { parsed, dispatched };
}

/** The configuration boot parsed, as {@link bootDispatched} boots it. */
async function bootParsed(
	env: Record<string, string>,
	configEnv = "production",
	operatorLayer?: string,
	modules: readonly Module[] = [],
): Promise<AppConfig> {
	return (await bootDispatched(env, configEnv, operatorLayer, modules)).parsed;
}

/** `session-store {}` as the session store's module parses it. */
function sessionStoreSection(config: AppConfig): {
	readonly secure: boolean;
	readonly sameSite: string;
	readonly maxAge: number;
} {
	const schema = sessionStoreModule.section?.schema;
	if (schema === undefined) throw new Error("the session store's module declares no section");
	return schema.parse((config as Record<string, unknown>)["session-store"]) as ReturnType<
		typeof sessionStoreSection
	>;
}

/** `session {}` as the session module parses it. */
function sessionSection(config: AppConfig): { readonly csrf?: { readonly ttlSeconds: number } } {
	const schema = sessionModule.section?.schema;
	if (schema === undefined) throw new Error("the session module declares no section");
	return schema.parse(config.session) as ReturnType<typeof sessionSection>;
}

/** `http {}` as the `http` module parsed it, in a configuration boot parsed with the module loaded. */
function httpSectionOf(config: AppConfig): {
	readonly port: number;
	readonly readinessTimeoutMs: number;
	readonly trustProxy: unknown;
	readonly cors: { readonly allowedOrigins: readonly string[] };
} {
	return (config as unknown as { http: ReturnType<typeof httpSectionOf> }).http;
}

/** `oauth {}` as the oauth module's own schema parses it. */
function oauthSection(config: AppConfig): {
	readonly consentPage?: { readonly url: string };
	readonly clientIdMetadataDocuments?: Readonly<Record<string, unknown>>;
} {
	const schema = oauthEndpointsModule.section?.schema;
	if (schema === undefined) throw new Error("the oauth module declares no section");
	return schema.parse(config.oauth) as ReturnType<typeof oauthSection>;
}

/** Every `${?VAR}` in a HOCON layer, ignoring commented-out lines. */
function substitutionsIn(path: string): Set<string> {
	const found = new Set<string>();
	for (const line of readFileSync(path, "utf8").split("\n")) {
		const code = line.replace(/(^|\s)(#|\/\/).*$/, "");
		for (const match of code.matchAll(/\$\{\?([A-Z][A-Z0-9_]*)\}/g)) {
			found.add(match[1] as string);
		}
	}
	return found;
}

/**
 * Every variable named in a leading `| \`VAR\` |` cell of a README table.
 *
 * The underscore is what separates an environment variable from the HTTP
 * methods in the endpoint table, which share the shouting-case shape.
 */
function documentedInReadme(path: string = readmePath): Set<string> {
	const found = new Set<string>();
	for (const match of readFileSync(path, "utf8").matchAll(/^\|\s*`([A-Z][A-Z0-9_]*)`\s*\|/gm)) {
		const name = match[1] as string;
		if (name.includes("_")) found.add(name);
	}
	return found;
}

/**
 * The substitutions of the template's own layers, and of the `reference.conf`
 * of every package the template loads a module from under the documented
 * environment in production (core's among them) — and under it with MFA
 * installed, its factors in the Store, which brings the MFA package's and
 * foundation's.
 */
function liveSubstitutions(): Set<string> {
	const { applicationConfPath } = resolveConfigPaths(configDir, "production");
	const references = [
		DOCUMENTED_ENV,
		{ ...DOCUMENTED_ENV, MFA_MODE: "required", ADAPTERS_MFA_FACTOR_STORE: "store" },
	].flatMap((env) =>
		moduleReferences(buildModules(readShippedSwitches(env), { environment: "production" })),
	);
	return new Set([
		...references.flatMap((reference) => [...substitutionsIn(fileURLToPath(reference))]),
		...substitutionsIn(fileURLToPath(templateReference())),
		...substitutionsIn(applicationConfPath),
	]);
}

describe("the shipped config boots with every documented override supplied as a string", () => {
	it("parses with every documented environment variable set", async () => {
		await expect(bootParsed(DOCUMENTED_ENV)).resolves.toBeDefined();
	});

	it("turns every boolean override into an actual boolean", async () => {
		const config = await bootParsed(DOCUMENTED_ENV);
		// Each of these arrives from HOCON as a string. A leftover string is
		// not a cosmetic defect: `=== true` is how the runtime reads them.
		expect(sessionStoreSection(config).secure).toBe(false);
		expect(config.oauth.jwt.legacyTypAccept).toBe(true);
		expect(config.oauth.requireEmailVerified).toBe(true);
		expect(config.oauth.resourceIndicator?.enabled).toBe(true);
		expect(config.core?.federations?.google?.enabled).toBe(true);
		expect(config.core?.federations?.oidc?.enabled).toBe(true);
		// A leftover string here would be read as "on" by a truthiness check
		// and as "off" by `=== true`, for a feature whose whole default is off.
		expect(config["federation-grants"]?.enabled).toBe(true);
	});

	it("turns every non-boolean override into its declared type", async () => {
		const config = await bootParsed(DOCUMENTED_ENV);
		const http = httpSectionOf(
			await bootParsed(DOCUMENTED_ENV, "production", undefined, [httpModule]),
		);
		expect(http.port).toBe(3000);
		expect(http.readinessTimeoutMs).toBe(1500);
		expect(http.trustProxy).toEqual(["10.0.0.0/8", "loopback"]);
		expect(config.core?.federations?.google?.accessType).toBe("online");
		// The new default wins over the deprecated variable, and the parsed
		// config mirrors it onto the old key for readers that predate the split.
		expect(resolveAccessTokenLifetime(config)).toEqual({
			defaultExpiresIn: 900,
			maxExpiresIn: 7200,
		});
		expect(config.oauth.accessToken.expiresIn).toBe(900);
		expect(config.oauth.refreshToken.expiresIn).toBe(86400);
		expect(sessionStoreSection(config).maxAge).toBe(3600000);
		expect(sessionSection(config).csrf?.ttlSeconds).toBe(7200);
		expect(config.oauth.nonce?.maxLength).toBe(256);
		expect(readShippedSwitches(DOCUMENTED_ENV).adapters.consentStore).toBe("redis");
		// A Redis store's section, which its module (not loaded here) parses.
		const sections = config as unknown as Record<string, { keyPrefix?: unknown } | undefined>;
		expect(sections["redis-consent-store"]?.keyPrefix).toBe("tenant-a:consent:");
		// The comma-separated lists become lists, trimmed; the numbers, numbers:
		// the oauth module's schema reads them (the module is not loaded here).
		expect(oauthSection(config).clientIdMetadataDocuments).toEqual({
			enabled: true,
			allowedScopes: ["read", "write"],
			allowedAudiences: ["https://mcp.example"],
			allowedHosts: ["client.example", ".trusted.example"],
			deniedHosts: ["evil.example"],
			maxBytes: 8192,
			timeoutMs: 3000,
			maxCacheEntries: 128,
			staleIfErrorMs: 120000,
			negativeCacheMs: 30000,
			maxConcurrentFetches: 4,
			cacheMaxAgeMs: 60000,
		});
		// The MFA switch is read before boot, by the template; off, it hands
		// boot no `mfa` section.
		expect(readShippedSwitches(DOCUMENTED_ENV).mfaMode).toBe("off");
		expect(config).not.toHaveProperty("mfa");
		expect(config).not.toHaveProperty("endpoints.mfa");
		expect(readShippedSwitches(DOCUMENTED_ENV).adapters).toMatchObject({
			mfaFactorStore: "redis",
			mfaTransactionStore: "redis",
		});
		expect(sections["redis-mfa-factor-store"]?.keyPrefix).toBe("tenant-a:mfaf:");
		expect(sections["redis-mfa-transaction-store"]?.keyPrefix).toBe("tenant-a:mfat:");
		// A comma-separated string becomes a list of origins, trimmed.
		expect(http.cors.allowedOrigins).toEqual(["https://app.example.com", "http://localhost:5173"]);
	});

	describe("the federations' variables, read by each federation's type", () => {
		it("hands each enabled federation's type the entry its documented variables set", async () => {
			const { dispatched } = await bootDispatched(DOCUMENTED_ENV);
			expect(Object.fromEntries(dispatched)).toEqual({
				google: {
					callbackURL: DOCUMENTED_ENV.CORE_FEDERATIONS_GOOGLE_CALLBACK_URL,
					entry: {
						clientId: DOCUMENTED_ENV.CORE_FEDERATIONS_GOOGLE_CLIENT_ID,
						clientSecret: DOCUMENTED_ENV.CORE_FEDERATIONS_GOOGLE_CLIENT_SECRET,
						redirectAllowlist: [],
						accessType: "online",
					},
				},
				oidc: {
					callbackURL: DOCUMENTED_ENV.CORE_FEDERATIONS_OIDC_CALLBACK_URL,
					entry: {
						issuer: DOCUMENTED_ENV.CORE_FEDERATIONS_OIDC_ISSUER,
						clientId: DOCUMENTED_ENV.CORE_FEDERATIONS_OIDC_CLIENT_ID,
						clientSecret: DOCUMENTED_ENV.CORE_FEDERATIONS_OIDC_CLIENT_SECRET,
						scopes: ["openid", "profile", "email"],
						redirectAllowlist: [],
					},
				},
			});
		});

		it("reads the Google keys the configuration documents commented out, bound as their comments write them", async () => {
			const { dispatched } = await bootDispatched(
				{ ...DOCUMENTED_ENV, ...COMMENTED_FEDERATION_ENV },
				"production",
				commentedFederationBindings(),
			);
			expect(dispatched.get("google")?.entry).toEqual({
				clientId: DOCUMENTED_ENV.CORE_FEDERATIONS_GOOGLE_CLIENT_ID,
				clientSecret: DOCUMENTED_ENV.CORE_FEDERATIONS_GOOGLE_CLIENT_SECRET,
				redirectAllowlist: [],
				accessType: "online",
				sessionDomain: COMMENTED_FEDERATION_ENV.CORE_FEDERATIONS_GOOGLE_SESSION_DOMAIN,
				authCallbackUrl: COMMENTED_FEDERATION_ENV.CORE_FEDERATIONS_GOOGLE_AUTH_CALLBACK_URL,
				clientUrl: COMMENTED_FEDERATION_ENV.CORE_FEDERATIONS_GOOGLE_CLIENT_URL,
				requireAuthorizationResponseIss: false,
			});
			// `toEqual` passes a key present as `undefined`: no variable binds
			// `endSessionEndpoint`, so the entry must not carry the key at all.
			expect(dispatched.get("google")?.entry).not.toHaveProperty("endSessionEndpoint");
		});

		it("hands the Google type no key the documented variables leave unset, not even as undefined", async () => {
			const { dispatched } = await bootDispatched(DOCUMENTED_ENV);
			const entry = dispatched.get("google")?.entry;
			expect(entry).toBeDefined();
			for (const key of [
				"sessionDomain",
				"authCallbackUrl",
				"clientUrl",
				"requireAuthorizationResponseIss",
				"endSessionEndpoint",
			]) {
				expect(entry, key).not.toHaveProperty(key);
			}
		});

		it("binds every variable the configuration documents commented out", () => {
			expect(
				commentedFederationBindings()
					.match(/\$\{\?[A-Z0-9_]+\}/g)
					?.sort(),
			).toEqual(
				Object.keys(COMMENTED_FEDERATION_ENV)
					.map((name) => `\${?${name}}`)
					.sort(),
			);
		});

		/** The entry the Google type was handed under `variables`, the commented keys bound. */
		const googleEntryUnder = async (variables: Record<string, string>) =>
			(
				await bootDispatched(
					{ ...DOCUMENTED_ENV, ...variables },
					"production",
					commentedFederationBindings(),
				)
			).dispatched.get("google")?.entry;

		for (const [supplied, expected] of [
			["true", true],
			["TRUE", true],
			["1", true],
			["false", false],
			["False", false],
			[" false ", false],
			["0", false],
		] as const) {
			it(`CORE_FEDERATIONS_GOOGLE_REQUIRE_AUTHORIZATION_RESPONSE_ISS=${JSON.stringify(supplied)} reads as ${expected}`, async () => {
				const entry = await googleEntryUnder({
					CORE_FEDERATIONS_GOOGLE_REQUIRE_AUTHORIZATION_RESPONSE_ISS: supplied,
				});
				expect(entry?.requireAuthorizationResponseIss).toBe(expected);
			});
		}

		it("refuses CORE_FEDERATIONS_GOOGLE_REQUIRE_AUTHORIZATION_RESPONSE_ISS exported empty or misspelt, naming the key, rather than turning the check off", async () => {
			for (const supplied of ["", "no", "off", "ture"]) {
				await expect(
					googleEntryUnder({
						CORE_FEDERATIONS_GOOGLE_REQUIRE_AUTHORIZATION_RESPONSE_ISS: supplied,
					}),
					supplied,
				).rejects.toThrow(/core\.federations\.google\.requireAuthorizationResponseIss/);
			}
		});

		it("reads CORE_FEDERATIONS_GOOGLE_ACCESS_TYPE as offline or online, exactly", async () => {
			for (const supplied of ["offline", "online"]) {
				expect(
					(await googleEntryUnder({ CORE_FEDERATIONS_GOOGLE_ACCESS_TYPE: supplied }))?.accessType,
				).toBe(supplied);
			}
			for (const supplied of ["", "Online", "offine", "true"]) {
				await expect(
					googleEntryUnder({ CORE_FEDERATIONS_GOOGLE_ACCESS_TYPE: supplied }),
					supplied,
				).rejects.toThrow(/core\.federations\.google\.accessType/);
			}
		});
	});

	describe("HTTP_CORS_ALLOWED_ORIGINS", () => {
		it("reads an exported-but-empty variable as no origins, not as an error", async () => {
			// The .env / compose / ConfigMap shape. "CORS off" is what both the
			// unset key and the empty string mean, so they must agree.
			const config = await bootParsed(
				{ ...DOCUMENTED_ENV, HTTP_CORS_ALLOWED_ORIGINS: "" },
				"production",
				undefined,
				[httpModule],
			);
			expect(httpSectionOf(config).cors.allowedOrigins).toEqual([]);
		});

		it("fails boot on an origin that could never match, naming the key", async () => {
			// Every one of these parses as a URL and is a real typo: matching is
			// exact string equality against the Origin header, so each would be
			// an allowlist that admits nobody with nothing to say so.
			for (const bad of [
				"https://app.example.com/", // trailing slash
				"https://app.example.com:443", // explicit default port
				"https://*.example.com", // wildcard
				"http://app.example.com", // plaintext off loopback
				"https://app.example.com/callback", // a URL, not an origin
			]) {
				await expect(
					bootParsed(
						{ ...DOCUMENTED_ENV, HTTP_CORS_ALLOWED_ORIGINS: bad },
						"production",
						undefined,
						[httpModule],
					),
				).rejects.toThrow(/http\.cors\.allowedOrigins/);
			}
		});

		it("fails boot on a value that is neither a list nor a string, naming the key", async () => {
			// The variable can only ever carry a string, so this shape comes
			// from a configuration file. Read as no origins, it would turn CORS
			// silently off for a key someone wrote.
			for (const value of ["42", "true", '{ origin = "https://app.example.com" }']) {
				await expect(
					bootParsed(DOCUMENTED_ENV, "production", `http.cors.allowedOrigins = ${value}`, [
						httpModule,
					]),
					value,
				).rejects.toThrow(/http\.cors\.allowedOrigins/);
			}
		});

		it("accepts the loopback http carve-out a dev front-end needs", async () => {
			const config = await bootParsed(
				{
					...DOCUMENTED_ENV,
					HTTP_CORS_ALLOWED_ORIGINS:
						"http://localhost:5173,http://127.0.0.1:5173,https://app.example.com",
				},
				"production",
				undefined,
				[httpModule],
			);
			expect(httpSectionOf(config).cors.allowedOrigins).toHaveLength(3);
		});
	});

	it("parses the HS256 shape, whose strict union refuses asymmetric key fields", async () => {
		// `KEY_STORE_LOCAL_ALGORITHM=HS256` is not a variation on the map above:
		// the HS256 member of the key store's `local` union is strict, so a
		// deployment that switches algorithm must also stop exporting the
		// key-file variables. Worth pinning — it is the umbrella E2E's shape.
		const { KEY_STORE_LOCAL_PRIVATE_KEY, KEY_STORE_LOCAL_PRIVATE_KEY_PATH, ...rest } =
			DOCUMENTED_ENV;
		void KEY_STORE_LOCAL_PRIVATE_KEY;
		void KEY_STORE_LOCAL_PRIVATE_KEY_PATH;
		const { KEY_STORE_LOCAL_PUBLIC_KEY, KEY_STORE_LOCAL_PUBLIC_KEY_PATH, ...hs256 } = rest;
		void KEY_STORE_LOCAL_PUBLIC_KEY;
		void KEY_STORE_LOCAL_PUBLIC_KEY_PATH;
		const config = await bootParsed(
			{ ...hs256, KEY_STORE_LOCAL_ALGORITHM: "HS256" },
			"production",
			undefined,
			[keyStoreModule],
		);
		expect(
			(config as unknown as { "key-store": { local: { algorithm: string } } })["key-store"].local
				.algorithm,
		).toBe("HS256");
	});

	it("parses the environment the umbrella E2E boots, with SESSION_STORE_SECURE=false as a string", async () => {
		const config = await bootParsed(UMBRELLA_E2E_ENV);
		expect(sessionStoreSection(config).secure).toBe(false);
		expect(config.oauth.requireEmailVerified).toBe(true);
		expect(config.oauth.resourceIndicator?.enabled).toBe(true);
		expect(config.core?.deployment?.mode).toBe("multi");
	});

	it("wires nothing replica-unsafe for the umbrella E2E environment", async () => {
		// `CORE_DEPLOYMENT_MODE=multi` makes the provider audit its own store wiring
		// at boot, so a config that parses but wires a memory store still fails
		// there. Ask each manifest, the way the guard does: the exported name
		// list covers core's modules only, and cannot see the template's own
		// memory modules.
		const { replicaUnsafeReason } = await import("@o3co/auth-provider-core");
		// Each module's section at its name: a declaration made from the
		// section is answered for it.
		const own = readOwnLayers(ownFiles("production"), { env: UMBRELLA_E2E_ENV });
		const switches = readSwitches(own);
		const modules = buildModules(switches);
		const sections = resolveForBoot(own, modules, switches) as unknown as Record<string, unknown>;
		for (const module of modules) {
			expect(replicaUnsafeReason(module, sections[module.name]), module.name).toBeUndefined();
		}
	});

	it("reads MFA_MODE=off before boot, where the shipped configuration expects no session requirement", async () => {
		expect(readShippedSwitches({ ...DOCUMENTED_ENV, MFA_MODE: "off" }).mfaMode).toBe("off");
		const parsed = await bootParsed({ ...DOCUMENTED_ENV, MFA_MODE: "off" });
		expect(parsed.core?.sessionRequirements).toEqual({ expected: [] });
	});

	describe("boolean overrides accept the spellings an operator writes", () => {
		const cases: ReadonlyArray<[string, boolean]> = [
			["true", true],
			["TRUE", true],
			["1", true],
			["false", false],
			["0", false],
			// An exported-but-empty variable — the `.env` / compose / ConfigMap
			// shape. Reads as false, as it does for trustProxy.
			["", false],
		];

		for (const [supplied, expected] of cases) {
			it(`SESSION_STORE_SECURE=${JSON.stringify(supplied)} resolves to ${expected}`, async () => {
				const config = await bootParsed({
					...DOCUMENTED_ENV,
					SESSION_STORE_SECURE: supplied,
					SESSION_STORE_SAME_SITE: "lax",
				});
				expect(sessionStoreSection(config).secure).toBe(expected);
			});

			it(`OAUTH_JWT_LEGACY_TYP_ACCEPT=${JSON.stringify(supplied)} resolves to ${expected}`, async () => {
				const config = await bootParsed({
					...DOCUMENTED_ENV,
					OAUTH_JWT_LEGACY_TYP_ACCEPT: supplied,
				});
				expect(config.oauth.jwt.legacyTypAccept).toBe(expected);
			});
		}

		it("refuses a spelling it does not recognise rather than guessing", async () => {
			const config = await bootParsed({ ...DOCUMENTED_ENV, SESSION_STORE_SECURE: "ture" });
			expect(() => sessionStoreSection(config)).toThrow(/true.*false/s);
		});

		it("refuses SESSION_STORE_SAME_SITE=none unless SESSION_STORE_SECURE is on", async () => {
			// The SameSite=None guard reads the coerced value, so it has to keep firing
			// for the string form an environment variable actually delivers.
			const insecure = await bootParsed({
				...DOCUMENTED_ENV,
				SESSION_STORE_SAME_SITE: "none",
				SESSION_STORE_SECURE: "false",
			});
			expect(() => sessionStoreSection(insecure)).toThrow(/SESSION_STORE_SECURE=true/);
			const secure = await bootParsed({
				...DOCUMENTED_ENV,
				SESSION_STORE_SAME_SITE: "none",
				SESSION_STORE_SECURE: "true",
				SESSION_STORE_NAME: "auth.session",
			});
			expect(sessionStoreSection(secure).sameSite).toBe("none");
		});
	});

	describe("the documented surface and this suite cannot drift apart", () => {
		it("covers every substitution the shipped config layers declare", () => {
			const uncovered = [...liveSubstitutions()].filter(
				(name) => !(name in DOCUMENTED_ENV) && !(name in DELIBERATELY_UNSET),
			);
			expect(uncovered).toEqual([]);
		});

		it("covers every environment variable the README documents", () => {
			const uncovered = [...documentedInReadme(), ...documentedInReadme(readmeJaPath)].filter(
				(name) => !(name in DOCUMENTED_ENV) && !(name in DELIBERATELY_UNSET),
			);
			expect(uncovered).toEqual([]);
		});

		it("documents the same variables in README.md and README.ja.md", () => {
			// The Japanese README carries the same facts (AGENTS.md): a row added
			// to one and not the other is a variable one audience never hears of.
			const en = documentedInReadme();
			const ja = documentedInReadme(readmeJaPath);
			expect({
				onlyInEnglish: [...en].filter((name) => !ja.has(name)).sort(),
				onlyInJapanese: [...ja].filter((name) => !en.has(name)).sort(),
			}).toEqual({ onlyInEnglish: [], onlyInJapanese: [] });
		});

		it("exercises no variable the config layers no longer substitute", () => {
			// Catches the reverse drift: a README row (and a test entry) left
			// behind by a key that was removed from the HOCON.
			const live = liveSubstitutions();
			const dead = Object.keys(DOCUMENTED_ENV).filter((name) => !live.has(name));
			expect(dead).toEqual([]);
		});
	});

	describe("variables whose documented behaviour is to fail boot", () => {
		it("refuses OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS, naming allowUnmarkedClients", async () => {
			await expect(
				bootParsed({
					...DOCUMENTED_ENV,
					OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS: "true",
				}),
			).rejects.toThrow(/allowUnmarkedClients/);
		});

		it("refuses an access-token default above the max, naming both keys", async () => {
			await expect(
				bootParsed({
					...DOCUMENTED_ENV,
					OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN: "7200",
					OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN: "3600",
				}),
			).rejects.toThrow(/defaultExpiresIn.*maxExpiresIn/s);
		});

		for (const name of [
			"OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN",
			"OAUTH_ACCESS_TOKEN_MAX_EXPIRES_IN",
			"OAUTH_ACCESS_TOKEN_EXPIRES_IN",
		]) {
			it(`refuses an empty ${name} rather than minting already-expired tokens`, async () => {
				await expect(bootParsed({ ...DOCUMENTED_ENV, [name]: "" })).rejects.toThrow();
			});
		}

		it("refuses MFA_MODE that is none of the three before boot, naming mfaMode", async () => {
			const env = { ...DOCUMENTED_ENV, MFA_MODE: "on" };
			expect(() => readShippedSwitches(env)).toThrow(RangeError);
			await expect(bootParsed(env)).rejects.toThrow(/mfaMode/);
		});

		for (const mode of ["optional", "required"] as const) {
			it(`reads MFA_MODE=${mode} as the switch that installs MFA, expecting mfa`, () => {
				const own = readOwnLayers(ownFiles("production"), {
					env: { ...DOCUMENTED_ENV, MFA_MODE: mode },
				});
				const switches = readSwitches(own);
				expect(switches.mfaMode).toBe(mode);
				const shipped = (resolveLayers(own, []).core as { sessionRequirements?: unknown })
					.sessionRequirements;
				expect(expectedSessionRequirements(shipped, switches.mfaMode)).toEqual({
					expected: ["mfa"],
					secondFactorAuthority: "mfa",
				});
			});
		}

		it("refuses DEPLOYMENT_MODE set alone, naming CORE_DEPLOYMENT_MODE", async () => {
			const { CORE_DEPLOYMENT_MODE: _new, ...env } = DOCUMENTED_ENV;
			await expect(bootParsed({ ...env, DEPLOYMENT_MODE: "multi" })).rejects.toThrow(
				/DEPLOYMENT_MODE was renamed CORE_DEPLOYMENT_MODE/,
			);
		});

		it("still refuses an empty SESSION_CSRF_TTL_SECONDS", async () => {
			// Pinned alongside the boolean cases because it is the same trap
			// read from the other side: for a *number*, empty means fail loudly.
			const config = await bootParsed({ ...DOCUMENTED_ENV, SESSION_CSRF_TTL_SECONDS: "" });
			expect(() => sessionSection(config)).toThrow(/ttlSeconds/);
		});
	});

	it("resolves against the shipped standalone artifact, not a fixture", () => {
		// Guards the guard: if the paths above ever stop pointing at the real
		// artifact these tests would pass while testing nothing. Checked by
		// what the directory holds, not by what it is called: this file ships
		// in every scaffolded project, and none of those lives at
		// `templates/standalone`.
		for (const file of ["config/application.conf", "config/production.conf", "src/app.mts"]) {
			expect(existsSync(join(standaloneDir, file)), file).toBe(true);
		}
		expect(liveSubstitutions().size).toBeGreaterThan(40);
	});
});
