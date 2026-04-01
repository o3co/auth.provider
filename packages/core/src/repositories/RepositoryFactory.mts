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

export type RepositoryBuilder<T> = (config: Record<string, unknown>) => Promise<T> | T;

export class RepositoryFactory<T> {
	private builders = new Map<string, RepositoryBuilder<T>>();
	private readonly label: string;

	constructor(label: string) {
		this.label = label;
	}

	register(type: string, builder: RepositoryBuilder<T>): void {
		this.builders.set(type, builder);
	}

	async create(config: { type: string; [key: string]: unknown }): Promise<T> {
		const builder = this.builders.get(config.type);
		if (!builder) {
			const registered = [...this.builders.keys()];
			const suffix =
				registered.length > 0
					? `Registered types: ${registered.join(", ")}`
					: "No types registered";
			throw new Error(`Unknown ${this.label} repository type: "${config.type}". ${suffix}`);
		}
		return builder(config);
	}
}
