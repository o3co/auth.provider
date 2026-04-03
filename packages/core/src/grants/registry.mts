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
import type { GrantDependencies, GrantHandler, GrantModule } from "./types.mjs";

export class GrantRegistry {
	private handlers = new Map<string, GrantHandler>();

	register(grantType: string, handler: GrantHandler): void {
		this.handlers.set(grantType, handler);
	}

	get(grantType: string): GrantHandler | undefined {
		return this.handlers.get(grantType);
	}

	addModule(module: GrantModule, deps: GrantDependencies): void {
		for (const [name, factory] of Object.entries(module.grants)) {
			const grantConfig = (
				deps.config.oauth.grants as Record<string, { enabled?: boolean }>
			)[name];
			if (grantConfig?.enabled === false) continue;
			this.register(name, factory(deps));
		}
	}

	cleanup(): void {
		for (const handler of this.handlers.values()) {
			handler.cleanup?.();
		}
	}
}
