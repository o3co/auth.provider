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
 * The two manifests this package installs (#593, D9–D12).
 *
 * ### Why a package, and not `/oauth/token`
 *
 * What these routes disclose is an *upstream* access token, held on a user's
 * standing consent, for a backend the user is not present at. Behind
 * `/oauth/token` it would inherit grant dispatch, `token.issued`, this
 * provider's token minting and a sender-constraint policy that cannot bind a
 * credential another issuer minted. Inside the oauth package it would make an
 * optional feature part of every deployment's routing surface, so enabling
 * ordinary OAuth would acquire this lifecycle by accident.
 *
 * ### Why two modules
 *
 * `federationGrantBackgroundModule` provides the registry that a shutdown
 * drains; `federationGrantsModule` mounts the routes and requires it. They are
 * separate because their dependency edges point in different directions: the
 * registry must be built *after* the store, the revocation boundary and the
 * sink so that its cleanup runs *before* theirs, while the routes need nothing
 * of the sort. Install them together —
 *
 *     modules: [...federationGrantsModules, ...]
 *
 * — which is what {@link federationGrantsModules} is for. Mounting the routes
 * without the registry is a boot refusal rather than a shutdown that silently
 * drops rotated credentials.
 *
 * ### Secure-default opt-in
 *
 * `federationGrants.enabled = false` in `reference.conf`. Installing a package
 * must not turn on offline delegation; the operator says so. A disabled
 * deployment answers the same 404 a deployment without the package answers,
 * and reads none of the feature's configuration or components on the way.
 */

import { coerceBooleanFromEnv, defineModule } from "@o3co/auth-provider-core";
import express, { type RequestHandler } from "express";
import { z } from "zod";
import { createFederationGrantBackground } from "./background.mjs";
import { createRequestIdMiddleware } from "./requestId.mjs";
import { FEDERATION_GRANTS_MOUNT_PATH } from "./types.mjs";

/**
 * The slice both routes read. Core's `fullSectionsSchema` declares the whole
 * `federationGrants` block — it has to, since the standalone validates against
 * it before any module's `configSchema` runs and would otherwise strip what
 * only this package knew about — so what is restated here is the one key this
 * module reads, and its default.
 *
 * `coerceBooleanFromEnv` rather than `z.boolean()` (#288): HOCON substitutes
 * `${?FEDERATION_GRANTS_ENABLED}` as a string, always.
 */
export const federationGrantsConfigSchema = z.object({
	federationGrants: z
		.object({ enabled: coerceBooleanFromEnv.default(false) })
		.default({ enabled: false }),
});

// biome-ignore lint/suspicious/noExplicitAny: planner-inferred deps shape — the manifest reads only slots it declares in `requires` / `optional`
type AnyDeps = any;

const isEnabled = (deps: AnyDeps): boolean =>
	(deps.config as { federationGrants?: { enabled?: boolean } }).federationGrants?.enabled === true;

/**
 * §5 refusal 1. An enabled deployment with nowhere to keep grants would
 * authenticate a client and then answer 503 to everything, having accepted
 * `enabled = true` as if it meant something. The rest of the boot refusals
 * arrive with the routes whose dependencies they are about.
 */
const requireStore = (deps: AnyDeps): void => {
	if (deps.federationGrantStore === undefined) {
		throw new Error(
			"federationGrantsModule: federationGrants.enabled = true requires a " +
				"federationGrantStore component. A grant is a user's standing consent that " +
				"outlives their session, so there is nowhere to read one from and nothing to " +
				"write a rotated credential back to without it. Install the bundled memory " +
				"store (single replica only) or an adapter such as " +
				"redisFederationGrantStoreModule.",
		);
	}
};

/**
 * `Cache-Control` / `Pragma` on every exit, live or refused, ahead of anything
 * that can answer. A 404 with no directives is the shape an intermediary
 * caches heuristically, and a cached "this deployment has no federation
 * grants" would outlive the operator turning them on.
 */
const noStore: RequestHandler = (_req, res, next) => {
	res.set("Cache-Control", "no-store").set("Pragma", "no-cache");
	next();
};

/**
 * The last handler under the mount path: every method and sub-path this
 * package does not serve.
 *
 * The body carries no description, unlike the neighbouring packages' refusals.
 * That is the point of a disabled deployment: `{"error":"not_found"}` is
 * byte-identical to what a deployment without the package installed answers,
 * so an unauthenticated caller cannot learn that offline delegation is one
 * configuration key away. It is also the answer for a bad method on an enabled
 * deployment, where a description would be equally uninteresting — there is no
 * `GET` status alias to point anyone at.
 */
const notFound: RequestHandler = (_req, res) => {
	res.status(404).json({ error: "not_found" });
};

export const federationGrantBackgroundModule = defineModule({
	name: "federation-grant-background",
	/**
	 * Not read — and that is what they are for.
	 *
	 * `dispose()` runs component cleanups in reverse of the order the
	 * components were built in, so the registry's drain precedes the cleanup of
	 * everything it depends on. The work it is draining is writes *through*
	 * these: a rotated refresh token going into the store, an audit event going
	 * into the sink. An adapter that closed its client first would fail the
	 * write this drain exists to wait for.
	 *
	 * `optional`, not `requires`, because a deployment that installs the
	 * package and leaves the feature off must still boot with none of them —
	 * and an optional key produces the same ordering edge whenever a *module*
	 * fills it. A slot filled from `bootstrapComponents` is the host's own
	 * value, which the boot planner neither orders nor disposes of, so there is
	 * nothing to be ordered against.
	 */
	optional: ["federationGrantStore", "subjectRevocation", "auditSink"] as const,
	provides: {
		federationGrantBackground: () => createFederationGrantBackground(),
	},
	lifecycle: {
		federationGrantBackground: {
			cleanup: (background) => background.drain(),
		},
	},
});

export const federationGrantsModule = defineModule({
	name: "federation-grants",
	configSchema: federationGrantsConfigSchema,
	requires: ["config", "federationGrantBackground"] as const,
	optional: ["federationGrantStore"] as const,
	contributes: {
		routes: [
			(deps: AnyDeps) => {
				const router = express.Router();
				// Cache directives and correlation first, so that the one
				// response that escapes early is not the one with neither —
				// and they are the same on both branches, because a disabled
				// deployment must not be distinguishable by its headers.
				router.use(noStore);
				router.use(createRequestIdMiddleware());
				if (isEnabled(deps)) {
					requireStore(deps);
					// The rate-limit guard, the parsers, client authentication
					// and the two handlers are mounted here, ahead of the
					// terminal 404 below.
				}
				// Nothing feature-specific ran on a disabled deployment: no
				// component was read, no body was parsed, no client was
				// authenticated. That is the whole of what `enabled = false`
				// promises, and it is why the check is a branch here rather
				// than a refusal inside a handler.
				router.use(notFound);
				return {
					id: "federation-grants",
					mountPath: FEDERATION_GRANTS_MOUNT_PATH,
					handler: router,
				};
			},
		],
	},
});

/**
 * The documented installation form: `modules: [...federationGrantsModules]`.
 * The registry first, though the planner would sort them anyway — reading it
 * in dependency order is how the pair explains itself at a composition root.
 */
export const federationGrantsModules = [
	federationGrantBackgroundModule,
	federationGrantsModule,
] as const;
