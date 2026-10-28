import { selectionConsents } from "@mod/claims-selection";
import claimsSelection from "@mod/claims-selection/module";
import { claimsSelectionInMemory } from "@mod/claims-selection/testing";
import { type IdTokenMaker, idTokens, type RedemptionHook, redemptionHooks } from "@mod/code-grant";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	contract,
	defineModule,
	kernelConfig,
	type Module,
	type Runtime,
} from "@mod/kernel";
import keysModule from "@mod/keys/module";
import { keysConfig } from "@mod/keys/testing";
import secretHashModule from "@mod/secret-hash/module";
import { type AuthContext, sessions } from "@mod/session";
import { stubSessions } from "@mod/session/testing";
import subjectAttributes from "@mod/subject-attributes/module";
import { ledgers, userAttribute } from "@mod/users";
import usersModule from "@mod/users/module";
import { memoryUsersStores, usersConfig } from "@mod/users/testing";
import oidc from "../src/module.ts";

/** Sessions known by handle, entered as given. */
export const sessionsOf = (byHandle: Record<string, AuthContext> = {}) =>
	defineModule({ name: "sessions", replicaSafe: false, takes: [] }, (m) => [
		m.provide(sessions).by(() =>
			stubSessions({
				entryOf: async (handle) => {
					const context = byHandle[handle];
					return context === undefined
						? { kind: "absent" }
						: { kind: "entered", session: { id: handle, context }, endsAt: 1 };
				},
			}),
		),
	]);

/** A ledger that cannot look users up by subject. */
export const unanswering = defineModule({ name: "ledger", replicaSafe: false, takes: [] }, (m) => [
	m.contribute(ledgers).by(() => ({
		verify: async () => ({ kind: "none" }),
		bySubject: async () => ({ kind: "unanswerable" }),
	})),
]);

/** A session's context with the attributes a login kept under `source`. */
export const loginOf = (subject: string, source: string): AuthContext => ({
	subject,
	amr: ["pwd"],
	authenticatedAt: 0,
	attributes: {
		source,
		values: { email: "alice@login.example", [userAttribute.emailVerified]: true, name: "Al" },
	},
});

export const makers = contract<readonly IdTokenMaker[]>("makers");
export const hooks = contract<readonly RedemptionHook[]>("hooks");
/** A judge of consent that agrees to every scope, so a test selects by the client's allowance alone. */
const agreeing = defineModule({ name: "agreeing", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(selectionConsents).by(() => ({ consented: async () => true })),
]);
export const published = contract<readonly MetadataItem[]>("published");

/**
 * oidc with its dependencies. `config` is written over the defaults section by section;
 * `usersAs` stands in for users' modules, `sessionsAs` for the sessions subject-attributes reads.
 */
export const composed = (p: {
	readonly runtime: Runtime;
	readonly config?: Record<string, unknown>;
	readonly usersAs?: readonly Module[];
	readonly sessionsAs?: Module;
}) => ({
	modules: [
		http,
		keysModule,
		issuerModule,
		memoryUsersStores().module,
		...(p.usersAs ?? [usersModule]),
		secretHashModule,
		p.sessionsAs ?? sessionsOf(),
		subjectAttributes,
		claimsSelection,
		claimsSelectionInMemory().module,
		agreeing,
		oidc,
		defineModule(
			{ name: "reader", replicaSafe: true, takes: [idTokens, metadata, redemptionHooks] },
			(m) => [
				m.provide(makers).by((c) => c.collect(idTokens)),
				m.provide(hooks).by((c) => c.collect(redemptionHooks)),
				m.provide(published).by((c) => c.collect(metadata)),
			],
		),
	],
	config: {
		...kernelConfig(),
		...httpConfig(),
		...keysConfig(),
		...issuerConfig({ url: "https://as.example" }),
		...usersConfig([]),
		...p.config,
	},
	runtime: p.runtime,
});

/**
 * The composition of `composed`, assembled, with the tests' default redemption (`r-test`) pinned, as
 * code-grant pins each redemption before an ID token is made for it.
 */
export async function booted(p: Parameters<typeof composed>[0]) {
	const app = await assemble(composed(p));
	for (const hook of app.get(hooks)) await hook.pin("r-test");
	return app;
}
