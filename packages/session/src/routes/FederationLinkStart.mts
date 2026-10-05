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
 * The link start's checks, before any state is kept: the navigation came from
 * this site or a trusted origin, the Store can link, and the session cookie's
 * session is admitted as `session.link`. What it returns is the `sid` and
 * subject the callback links to.
 */

import {
	type Admission,
	auditErrorText,
	cookieClaim,
	type FederationProvider,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { checkNavigationOrigin } from "../csrf.mjs";
import type { LinkIntent } from "../federations/transaction.mjs";
import { admissionUnavailable } from "../internal/cookieSession.mjs";
import type { FederationRouterContext } from "./FederationContext.mjs";

/**
 * The link start's answer to a step-up: `403 step_up_required` with the
 * requirement and its registered page. The start is a browser navigation, so
 * the page it came from can send the user through the step-up and start
 * again; no return parameter is added, since that page knows where it
 * returns to.
 */
const stepUpRequired = (admission: Extract<Admission, { outcome: "step_up" }>) => ({
	error: "step_up_required",
	error_description: "Linking a federated identity requires a step-up first",
	requirement: admission.requirement,
	page: admission.page.href,
});

/**
 * Check a `?link=1` start. Answers and returns `null` when the link cannot
 * succeed; otherwise returns the link intent the transaction records.
 */
export const checkLinkStart = async (
	ctx: FederationRouterContext,
	provider: FederationProvider,
	req: Request,
	res: Response,
): Promise<LinkIntent | null> => {
	const { userRepository, logger, linkTrustedOrigins, admitLink } = ctx;
	// A link changes an existing account, so the user must be the one
	// asking: a top-level cross-site navigation carries the SameSite=Lax
	// cookie, and a forced `?link=1` paired with a login CSRF at the IdP
	// would link the attacker's identity to the victim's account. The
	// evidence is the session CSRF policy's navigation rule
	// (`checkNavigationOrigin`). An ordinary login start is not held to
	// this: cross-domain RPs starting a login is normal.
	if (checkNavigationOrigin(req, linkTrustedOrigins).outcome !== "accepted") {
		logger.warn(
			{
				provider: provider.name,
				// The caller's header, sanitised and capped like every
				// caller-controlled string on a log line.
				secFetchSite: auditErrorText(req.get("sec-fetch-site") ?? ""),
			},
			"federation_link_start_rejected",
		);
		res.status(403).json({
			error: "link_requires_trusted_origin",
			error_description:
				"Linking a federated identity must be started from this site or an origin on session.csrf.trustedOrigins",
		});
		return null;
	}
	// A Store that cannot link is the composition's fault, not the
	// session's: said first, before the session is read — a static
	// fault answers the same whatever the session store is doing.
	if (typeof userRepository.linkFederatedIdentity !== "function") {
		res.status(400).json({
			error: "link_unsupported",
			error_description: "The user repository does not support linking federated identities",
		});
		return null;
	}
	// Admitted as `session.link`, graded `credential_change` (a linked
	// identity is a new way into the account), so a recent-authentication
	// rule is decided here, where a step-up has a page to return to.
	const claim = cookieClaim(req);
	const admission = await admitLink(
		claim,
		"session.link",
		logger.child({ provider: provider.name }),
	);
	if (admission.outcome === "unavailable") {
		res.status(503).json(admissionUnavailable(admission.store));
		return null;
	}
	if (admission.outcome === "step_up") {
		res.status(403).json(stepUpRequired(admission));
		return null;
	}
	if (admission.outcome !== "admitted" || admission.session === null || claim.sid === undefined) {
		res.status(401).json({
			error: "login_required",
			error_description: "Linking a federated identity requires an authenticated session",
		});
		return null;
	}
	// Recorded in the transaction, not inferred later: the cookie's `sid`
	// and the admitted subject. A form_post callback arrives without the
	// session cookie, and a browser that switched accounts must not link
	// to the new one.
	return { sid: claim.sid, subject: admission.session.sub };
};
