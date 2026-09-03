export class GrantRegistry {
    handlers = new Map();
    register(grantType, handler) {
        this.handlers.set(grantType, handler);
    }
    get(grantType) {
        return this.handlers.get(grantType);
    }
    addModule(module, deps) {
        // Apply configSchema defaults when provided.
        // Pre-fill missing top-level keys with {} so nested defaults are applied in a single parse.
        const effectiveDeps = module.configSchema
            ? {
                ...deps,
                config: {
                    ...deps.config,
                    oauth: {
                        ...deps.config.oauth,
                        grants: {
                            ...deps.config.oauth.grants,
                            ...module.configSchema.parse(Object.fromEntries(Object.keys(module.grants).map((name) => [
                                name,
                                deps.config.oauth.grants[name] ?? {},
                            ]))),
                        },
                    },
                },
            }
            : deps;
        for (const [name, factory] of Object.entries(module.grants)) {
            const grantConfig = effectiveDeps.config.oauth.grants[name];
            if (grantConfig?.enabled === false)
                continue;
            this.register(name, factory(effectiveDeps));
        }
    }
    cleanup() {
        for (const handler of this.handlers.values()) {
            handler.cleanup?.();
        }
    }
}
