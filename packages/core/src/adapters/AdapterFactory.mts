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

export class AdapterFactoryError extends Error {
	public readonly kind: string;
	public readonly type: string;
	public readonly registered: readonly string[];

	constructor(args: { kind: string; type: string; registered: readonly string[] }) {
		const suffix =
			args.registered.length > 0
				? `Registered types: ${args.registered.join(", ")}`
				: "No types registered";
		super(
			`AdapterFactoryError [${args.kind}]: unknown type "${args.type}". ${suffix}`,
		);
		this.name = "AdapterFactoryError";
		this.kind = args.kind;
		this.type = args.type;
		this.registered = [...args.registered];
	}
}
