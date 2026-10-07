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
 * The scope and the targets a token exchange may name: the scope within the subject
 * token's and the client's `allowedScopes`, the audience within the client's
 * registration and the subject token's audience — requested, granted or defaulted —
 * and every resource equal to the audience the token is minted for. What the
 * request asks past them, or a default that lies past them, is refused.
 */
import { auditErrorList, readIssuedScope, readSpaceDelimitedParameter, readTargetParameter, } from "@o3co/auth-provider-core";
import { invalidRequest } from "./answers.mjs";
export function requestTargets(deps, body, client, subjectValidated) {
    // Scope: requested ⊆ subject scope ∩ client.allowedScopes. The registration is a
    // ceiling on every grant, so a client registered for `read` holding a subject
    // token with `admin` must not receive `admin`. Absent or empty `allowedScopes`
    // means no scope at all (deny by absence); a scope-less deployment still mints,
    // without a `scope` claim. Unlike the sibling grants, an omitted `scope`
    // inherits the subject's scope instead of reading `defaultScopes` (see
    // `grantedScope` in the policy hook).
    //
    // RFC 6749 §3.3, two readings: the subject's scope never widens
    // (`readIssuedScope`: a legacy `read<TAB>write` names no scope), and the
    // request's is strict (malformed is refused; a repeated parameter is refused
    // rather than read as omitted, which would inherit the subject's whole scope).
    const subjectScope = readIssuedScope(subjectValidated.scope);
    const subjectScopeSet = new Set(subjectScope);
    const clientScopeSet = new Set(client.allowedScopes ?? []);
    if (body.scope !== undefined && body.scope !== null && typeof body.scope !== "string") {
        return invalidRequest("scope must be a space-delimited string");
    }
    const requestedScopeRaw = typeof body.scope === "string" ? readSpaceDelimitedParameter(body.scope) : [];
    if (requestedScopeRaw === null) {
        return {
            result: {
                status: 400,
                error: "invalid_scope",
                errorDescription: "scope is not a space-delimited list of scope-tokens",
            },
        };
    }
    // Normalize empty to null — `scope=""` and `scope=" "` behave the same
    // as scope omitted (inherit subject scope), as a target parameter
    // that names nothing does below (RFC 6749 §3.2).
    const requestedScope = requestedScopeRaw.length === 0 ? null : requestedScopeRaw;
    if (requestedScope) {
        for (const s of requestedScope) {
            if (!subjectScopeSet.has(s)) {
                return {
                    result: {
                        status: 400,
                        error: "invalid_scope",
                        errorDescription: `scope '${s}' is not in subject_token scope`,
                    },
                };
            }
            // Named explicitly, so refused rather than dropped: a narrower token would
            // answer a different request than the one submitted.
            if (!clientScopeSet.has(s)) {
                return {
                    result: {
                        status: 400,
                        error: "invalid_scope",
                        errorDescription: `scope '${s}' is not allowed for this client`,
                    },
                };
            }
        }
    }
    // The audience ceilings: the client's registration (`allowedAudiences` plus its
    // own id) and the subject token's audience (see `subjectAudienceBoundary`). The
    // request is held to both before the policy runs, so its refusal is its own; a
    // policy's `grantedAudience` is held to the same two in the policy hook, and the
    // default an omitted audience takes to the same two in `issuedTarget`. The
    // subject's audience is read once, so the ceiling, the default and the final
    // check all see the one value.
    const clientAudienceSet = new Set([...(client.allowedAudiences ?? []), client.clientId]);
    const subjectAudienceSet = subjectAudienceBoundary(subjectValidated, client.clientId);
    // Targets are read by core's `readTargetParameter`. A value that is neither a
    // string nor an array of strings is refused, never converted
    // (`String([["billing"]])` is `"billing"`): `invalid_target` for `resource` (RFC
    // 8707 §2) and, by symmetry, `audience`. A target naming nothing is omitted (RFC
    // 6749 §3.2).
    const audienceValues = readTargetParameter(body.audience);
    if (audienceValues === null) {
        return {
            result: {
                status: 400,
                error: "invalid_target",
                errorDescription: "audience must be a string or an array of strings",
            },
        };
    }
    const resourceValues = readTargetParameter(body.resource);
    if (resourceValues === null) {
        return {
            result: {
                status: 400,
                error: "invalid_target",
                errorDescription: "resource must be a string or an array of strings",
            },
        };
    }
    const requestedAudience = audienceValues.length > 0 ? audienceValues : null;
    const requestedResource = resourceValues.length > 0 ? resourceValues : null;
    if (requestedAudience) {
        for (const aud of requestedAudience) {
            if (!clientAudienceSet.has(aud)) {
                return {
                    result: {
                        status: 400,
                        error: "invalid_target",
                        errorDescription: `audience '${aud}' is not allowed for this client`,
                    },
                };
            }
        }
        // An audience the client is registered for but the subject token does not carry:
        // `invalid_target` (RFC 8693 §2.2.2). De-duplicated, since `audience` may repeat.
        const widenedAudiences = [
            ...new Set(requestedAudience.filter((audience) => !subjectAudienceSet.has(audience))),
        ];
        if (widenedAudiences.length > 0) {
            return audienceWideningRefused(deps, client, subjectValidated, widenedAudiences);
        }
    }
    // A requested `resource` must equal the issued audience (RFC 8707, checked again
    // after the policy), which is an audience both the registration and the subject
    // token carry — the client id included, only when the subject token carries it. A
    // resource outside that set can never be represented, so it is the request's own
    // `invalid_target`, answered before a policy could turn it into a policy-ceiling
    // 500. It names every requested resource the request's own audience would not
    // equal or that lies outside the ceilings (the client id, when it is the default
    // and the subject token does not carry it).
    if (requestedResource) {
        const withinCeilings = (resource) => clientAudienceSet.has(resource) && subjectAudienceSet.has(resource);
        if (!requestedResource.every(withinCeilings)) {
            const requestAudience = issuedAudience(requestedAudience ?? undefined, subjectAudienceSet, clientAudienceSet, client.clientId);
            const missingResources = requestedResource.filter((resource) => resource !== requestAudience || !withinCeilings(resource));
            deps.logger?.warn({
                subject: subjectValidated.sub,
                clientId: client.clientId,
                audienceForToken: requestAudience,
                ...loggedResources(missingResources),
            }, "token_exchange_resource_not_in_audience");
            return {
                result: {
                    status: 400,
                    error: "invalid_target",
                    errorDescription: `requested_resources_not_in_audience: ${missingResources.join(" ")}`,
                },
            };
        }
    }
    return {
        subjectScope,
        subjectScopeSet,
        clientScopeSet,
        requestedScope,
        clientAudienceSet,
        subjectAudienceSet,
        requestedAudience,
        requestedResource,
    };
}
/**
 * The audience the token is minted for, within both audience ceilings whether it was
 * requested, granted or defaulted, and every requested resource held equal to it.
 */
export function issuedTarget(deps, client, subjectValidated, { clientAudienceSet, subjectAudienceSet, requestedResource, }, grantedAudience) {
    const audienceForToken = issuedAudience(grantedAudience, subjectAudienceSet, clientAudienceSet, client.clientId);
    if (requestedResource && requestedResource.length > 0) {
        const missingResources = requestedResource.filter((resource) => resource !== audienceForToken);
        if (missingResources.length > 0) {
            deps.logger?.warn({
                subject: subjectValidated.sub,
                clientId: client.clientId,
                audienceForToken,
                ...loggedResources(missingResources),
            }, "token_exchange_resource_not_in_audience");
            return {
                result: {
                    status: 400,
                    error: "invalid_target",
                    errorDescription: `requested_resources_not_in_audience: ${missingResources.join(" ")}`,
                },
            };
        }
    }
    // A requested or granted audience already met both ceilings; this holds the
    // default an omitted audience takes to them too. The client's own id is the one
    // default that can lie outside the subject token's audience, and it is refused
    // as a requested one would be. A requested resource reaching here equals the
    // audience and already met both, so only a request naming no resource is refused.
    if (!(clientAudienceSet.has(audienceForToken) && subjectAudienceSet.has(audienceForToken))) {
        return audienceWideningRefused(deps, client, subjectValidated, [audienceForToken]);
    }
    return { audienceForToken };
}
/** An audience outside the subject token's: `invalid_target` (RFC 8693 §2.2.2), logged. */
function audienceWideningRefused(deps, client, subjectValidated, widenedAudiences) {
    deps.logger?.warn({
        subject: subjectValidated.sub,
        clientId: client.clientId,
        widenedAudiences,
    }, "token_exchange_audience_widening_rejected");
    return {
        result: {
            status: 400,
            error: "invalid_target",
            errorDescription: `audience_widening_not_allowed: ${widenedAudiences.join(" ")}`,
        },
    };
}
/**
 * The requested resources a refusal logs: the first ten through core's
 * `auditErrorList` (sanitised, 200 characters each), plus `missingResourceCount`
 * when it had to cut. They are caller-controlled, so neither their content nor
 * their count may reach the log unbounded.
 */
const loggedResources = (resources) => {
    const missingResources = auditErrorList(resources);
    return missingResources.length < resources.length
        ? { missingResources, missingResourceCount: resources.length }
        : { missingResources };
};
/**
 * The single audience an exchanged token is minted for:
 * - an explicit audience (request or policy, already bounded): its first entry;
 * - omitted, with a subject audience of one value the client is registered for:
 *   that;
 * - otherwise the client's own id, so omitting `audience` cannot mint for an
 *   audience outside the client's allowlist. `issuedTarget` refuses it when the
 *   subject token's audience does not carry it.
 *
 * `generateToken` carries one audience, so only the first `grantedAudience` entry
 * is used; several audiences would need introspection by every party.
 */
function issuedAudience(grantedAudience, subjectAudienceSet, clientAudienceSet, clientId) {
    if (grantedAudience && grantedAudience.length > 0)
        return grantedAudience[0] ?? clientId; // `?? clientId` is forward-compat for noUncheckedIndexedAccess
    if (subjectAudienceSet.size === 1) {
        const [single] = subjectAudienceSet;
        if (single !== undefined && clientAudienceSet.has(single))
            return single;
    }
    return clientId;
}
/**
 * The subject token's audience, read from the validator's answer once: the
 * non-empty strings of its `aud`, de-duplicated. A subject token naming none is
 * read as naming the client's own id only when it is the client's own (its `azp`
 * is the client's id); a token of another client naming none names no audience,
 * so nothing is within it.
 */
function subjectAudienceBoundary(subjectValidated, clientId) {
    const audience = subjectValidated.aud;
    const values = (Array.isArray(audience) ? audience : [audience]).filter((value) => typeof value === "string" && value.length > 0);
    if (values.length > 0)
        return new Set(values);
    return new Set(subjectValidated.claims.azp === clientId ? [clientId] : []);
}
