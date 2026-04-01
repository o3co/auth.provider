/*
 * Copyright 2026 1o1 Inc.
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
import type { Request, Response } from "express";
import type { PassportStatic } from "passport";

import type { ClientRepository } from "#/repositories/ClientRepository.mjs";
import type { CodeRepository } from "#/repositories/CodeRepository.mjs";
import type { AppConfig } from "#/config/application.schema.mjs";

export interface GrantDependencies {
	config: AppConfig;
	clientRepository: ClientRepository;
	codeRepository: CodeRepository;
	passport: PassportStatic;
}

export interface GrantContext {
	req: Request;
	res: Response;
	issuer: string | undefined;
}

export interface GrantHandler {
	handle(ctx: GrantContext): Promise<void>;
	cleanup?(): void;
}

/**
 * Factory function type for creating grant handlers.
 * Used by OSS consumers to implement custom grant types.
 */
export type GrantFactory = (deps: GrantDependencies) => GrantHandler;
