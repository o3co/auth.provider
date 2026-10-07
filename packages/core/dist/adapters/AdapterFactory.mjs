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
 * Construct a fresh {@link AdapterFactory} for a single domain.
 *
 * @param kind human-readable label used in error messages (e.g. "UserRepository")
 * @param ctx  factory-level BuilderContext passed to every builder. Defaults to `{}`.
 */
export function createAdapterFactory(kind, ctx = {}) {
    const frozenCtx = Object.freeze({ ...ctx });
    const builders = new Map();
    return {
        register(type, builder) {
            if (builders.has(type)) {
                throw new AdapterFactoryError({
                    reason: "duplicate",
                    kind,
                    type,
                    registered: [...builders.keys()],
                });
            }
            builders.set(type, builder);
        },
        async create(config) {
            const builder = builders.get(config.type);
            if (!builder) {
                throw new AdapterFactoryError({
                    reason: "unknown",
                    kind,
                    type: config.type,
                    registered: [...builders.keys()],
                });
            }
            return builder(config, frozenCtx);
        },
        registeredTypes() {
            return [...builders.keys()];
        },
    };
}
export class AdapterFactoryError extends Error {
    reason;
    kind;
    type;
    registered;
    constructor(args) {
        const registeredSuffix = args.registered.length > 0
            ? `Registered types: ${args.registered.join(", ")}`
            : "No types registered";
        const detail = args.reason === "unknown"
            ? `unknown type "${args.type}"`
            : `type "${args.type}" is already registered`;
        super(`AdapterFactoryError [${args.kind}]: ${detail}. ${registeredSuffix}`);
        this.name = "AdapterFactoryError";
        this.reason = args.reason;
        this.kind = args.kind;
        this.type = args.type;
        this.registered = [...args.registered];
    }
}
