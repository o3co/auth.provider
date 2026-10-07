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
import { federationGrantIdentityRegistration } from "./acquisitionSettings.mjs";
/**
 * Check 5. The verified issuer is the connection's; a renewal's upstream account
 * is the one already on the grant; an expectation the client lodged is met; and,
 * unless the deployment recorded that it cannot ask, the Store establishes who
 * holds the upstream account: this user or nobody. Another user is a conflict.
 * An answer that establishes neither also refuses: "cannot tell" is not "linked
 * to nobody", and reading it so would let a pairwise `sub` through.
 */
export async function accountHolds({ options, now }, intent, connection, upstream) {
    const refused = (code, reason) => ({
        holds: false,
        code,
        ...(reason === undefined ? {} : { reason }),
    });
    /** Nothing could be established, and why: the redirect's `temporarily_unavailable`. */
    const unanswered = (at) => ({
        holds: false,
        code: "temporarily_unavailable",
        unanswered: at,
    });
    const LOOKUP = {
        store: "user_directory",
        step: "find_subject_by_federated_identity",
    };
    if (upstream.issuer !== connection.upstreamIssuer)
        return refused("upstream_error");
    if (intent.upstreamSubject !== undefined && upstream.subject !== intent.upstreamSubject) {
        return refused("account_mismatch");
    }
    if (intent.kind === "reauthorization") {
        try {
            const grant = await options.grantStore.find(intent.grantId, now());
            const recorded = grant !== null && grant.status !== "pending" ? grant.upstream : undefined;
            if (recorded === undefined ||
                recorded.issuer !== upstream.issuer ||
                recorded.subject !== upstream.subject) {
                return refused("account_mismatch");
            }
        }
        catch (error) {
            return unanswered({ store: "federation_grant", step: "find", error });
        }
    }
    if (options.identityLookup === "unsupported")
        return { holds: true, outcome: "unsupported" };
    // Called through the repository, never detached: a Store written as a class needs
    // its `this`.
    const repository = options.userRepository;
    if (typeof repository?.findSubjectByFederatedIdentity !== "function") {
        // Boot refused this under "required"; a repository that lost the
        // method since is a composition fault an operator must hear about.
        return unanswered({
            ...LOOKUP,
            error: new TypeError("the userRepository has no findSubjectByFederatedIdentity"),
        });
    }
    // Every claim the connection names, as the adapter verified it, or no question at
    // all: a lookup missing part of its evidence could answer "nobody". Only those
    // names reach the Store.
    const claims = requiredIdentityClaims(upstream.claims, connection.identityClaims ?? []);
    if (claims === undefined) {
        return refused("identity_unverifiable", "identity_claims_unavailable");
    }
    let answer;
    try {
        // The registration the identity was issued under — every part of it
        // the connection's configuration, the issuer already compared with the
        // verified one — so that a Store can place a `sub` that is pairwise
        // per registration.
        answer = lookupAnswer(await repository.findSubjectByFederatedIdentity({
            // The federation the exchange went through — the intent's, which
            // check 2 holds equal to the connection's: the name boot probed.
            ...federationGrantIdentityRegistration({
                federation: intent.federation,
                upstreamIssuer: connection.upstreamIssuer,
                upstreamClientId: connection.upstreamClientId,
            }),
            sub: upstream.subject,
            claims,
        }));
        if (answer === undefined) {
            throw new TypeError("the identity lookup answered something the port does not define");
        }
    }
    catch (error) {
        return unanswered({ ...LOOKUP, error });
    }
    switch (answer.kind) {
        case "linked":
            return answer.subject === intent.subject
                ? { holds: true, outcome: "required/linked" }
                : refused("identity_conflict");
        case "unlinked":
            return { holds: true, outcome: "required/unlinked" };
        case "indeterminate":
            return refused("identity_unverifiable", answer.reason);
    }
}
/**
 * The named claims out of what the adapter answered, as a fresh object, or
 * `undefined` if any is not an own, non-empty string.
 */
function requiredIdentityClaims(answered, names) {
    const claims = {};
    if (names.length === 0)
        return claims;
    // An array is an object, and `"0"` a legal claim name.
    if (typeof answered !== "object" || answered === null || Array.isArray(answered)) {
        return undefined;
    }
    for (const name of names) {
        if (!Object.hasOwn(answered, name))
            return undefined;
        const value = answered[name];
        if (typeof value !== "string" || value.length === 0)
            return undefined;
        claims[name] = value;
    }
    return claims;
}
/**
 * A lookup's answer if it is one the port defines, and `undefined` otherwise.
 * Recognised positively: any other shape (a bare string, `null`) must not fall
 * through to an outcome that lets a grant through.
 */
function lookupAnswer(value) {
    if (typeof value !== "object" || value === null)
        return undefined;
    const answer = value;
    switch (answer.kind) {
        case "linked":
            return typeof answer.subject === "string" && answer.subject.length > 0
                ? { kind: "linked", subject: answer.subject }
                : undefined;
        case "unlinked":
            return { kind: "unlinked" };
        case "indeterminate":
            return answer.reason === "registration_not_covered" ||
                answer.reason === "identity_not_resolvable"
                ? { kind: "indeterminate", reason: answer.reason }
                : undefined;
        default:
            return undefined;
    }
}
