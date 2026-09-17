export function createRouter(express, opts) {
    const router = express.Router();
    router.get("/.well-known/openid-configuration", (_req, res) => {
        const iss = opts.issuer.replace(/\/+$/, "");
        // JWKS is not served for symmetric-only deployments (HS256): the
        // public-key set is empty, so advertising jwks_uri would point
        // consumers at a 404. Only include jwks_uri when at least one
        // asymmetric alg is configured.
        const hasAsymmetricAlg = opts.signingAlgs.some((alg) => alg !== "HS256");
        return res.status(200).json({
            // Return the normalized issuer so it matches the `iss` claim minted
            // on tokens (both use trailing-slash-stripped form). Returning the
            // raw opts.issuer would cause RPs to reject tokens when iss differs
            // from discovery.issuer by a trailing slash.
            issuer: iss,
            authorization_endpoint: `${iss}/oauth/authorize`,
            token_endpoint: `${iss}/oauth/token`,
            userinfo_endpoint: `${iss}/oauth/userinfo`,
            ...(hasAsymmetricAlg ? { jwks_uri: `${iss}/.well-known/jwks.json` } : {}),
            introspection_endpoint: `${iss}/oauth/introspect`,
            // Logout discovery fields are only advertised when the logout router is mounted.
            // opts.logoutSupported defaults to false (explicit opt-in); oauthModule sets it
            // to the computed !!stores && !!issuer expression. Callers who use createRouter
            // directly must pass logoutSupported: true explicitly.
            ...(opts.logoutSupported === true
                ? {
                    end_session_endpoint: `${iss}/oauth/logout`,
                    backchannel_logout_supported: true,
                    backchannel_logout_session_supported: true,
                    frontchannel_logout_supported: true,
                    frontchannel_logout_session_supported: true,
                }
                : {}),
            response_types_supported: ["code"],
            subject_types_supported: ["public"],
            id_token_signing_alg_values_supported: [...opts.signingAlgs],
            // `groups` is supported by filterClaimsByScope (non-standard but opt-in)
            scopes_supported: ["openid", "profile", "email", "groups"],
            token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
            code_challenge_methods_supported: ["S256"],
        });
    });
    return router;
}
