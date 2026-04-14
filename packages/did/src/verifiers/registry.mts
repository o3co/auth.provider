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
import type { PathResolver } from "@o3co/auth-provider-core";

import type { SignatureVerifier } from "./types.mjs";

export type VerifierFactory = (pathResolver?: PathResolver) => Promise<SignatureVerifier>;

export class VerifierRegistry {
	private factories = new Map<string, VerifierFactory>();

	register(algorithm: string, factory: VerifierFactory): void {
		this.factories.set(algorithm, factory);
	}

	get(algorithm: string): VerifierFactory | undefined {
		return this.factories.get(algorithm);
	}

	has(algorithm: string): boolean {
		return this.factories.has(algorithm);
	}

	algorithms(): string[] {
		return [...this.factories.keys()];
	}
}
