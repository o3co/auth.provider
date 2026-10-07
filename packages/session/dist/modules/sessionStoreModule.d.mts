/**
 * D-5 / OR-M2: `sessionStoreModule` moves the express-session middleware
 * construction (previously inlined in `templates/standalone/src/app.mts`) into
 * the boot planner's DI graph so the underlying session-store client receives
 * a `BuilderContext.lifecycle` and can register `client.quit()` for disposal.
 *
 * The module contributes a route at `mountPath: "/"` whose handler is the
 * express-session RequestHandler. **Mount-order contract**: the route
 * intentionally has NO `before`/`after` clause, because referencing absent
 * downstream route ids would raise `route-order-target-missing` BootError on
 * partial manifests (e.g. an oauth-only deployment without sessionModule).
 * Mount order is enforced by **declarationIndex tie-breaking** — the
 * composition root MUST list `sessionStoreModule` ahead of every
 * session-consuming module in `buildModules(config)`.
 *
 * Standalone composition root: drop the manual `app.use(session(...))` block
 * and prepend `sessionStoreModule` to `buildModules(config)`. The session
 * middleware is mounted inside `handle.router`, ordered first by list
 * position. See CHANGELOG v0.5.1 D-5 BREAKING entry for the migration note.
 */
export declare const sessionStoreModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=sessionStoreModule.d.mts.map