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
import type { AppConfig } from "#/config/application.schema.mjs";
import type { ClientRepository } from "#/repositories/ClientRepository.mjs";
import type { CodeRepository } from "#/repositories/CodeRepository.mjs";

export interface SessionData {
	user?: Record<string, unknown>;
	client?: Record<string, unknown>;
	code?: string;
	code_client_id?: string;
	granted_scopes?: string[];
	isAuthenticated?: boolean;
}

export interface GrantContext {
	body: Record<string, unknown>;
	session: SessionData;
	issuer?: string;
	metadata: Record<string, unknown>;
}

export interface GrantSuccess {
	status: number;
	tokens: import("./token.mjs").TokenResponse;
}

export interface GrantError {
	status: number;
	error: string;
	errorDescription?: string;
}

export type GrantResult = GrantSuccess | GrantError;

export interface SessionMutation {
	clear?: string[];
	set?: Record<string, unknown>;
}

export interface GrantHandlerResult {
	result: GrantResult;
	sessionMutation?: SessionMutation;
}

export interface GrantHandler {
	handle(ctx: GrantContext): Promise<GrantHandlerResult>;
	cleanup?(): void;
}

export interface GrantDependencies {
	config: AppConfig;
	clientRepository: ClientRepository;
	codeRepository: CodeRepository;
}

/**
 * Factory function type for creating grant handlers.
 * Used by OSS consumers to implement custom grant types.
 */
export type GrantFactory = (deps: GrantDependencies) => GrantHandler;
