/**
 * The actions this package admits, grouped by the module that registers them,
 * each exercising the session (`use`). `createOAuthRouter` admits the first
 * group; each session-bound grant admits its own.
 */
/** What `createOAuthRouter` admits: `/authorize` and the consent step. */
export declare const OAUTH_ROUTER_ADMISSION_ACTIONS: Readonly<{
    readonly "oauth.authorize": Readonly<{
        grade: "use";
    }>;
    readonly "oauth.consent": Readonly<{
        grade: "use";
    }>;
}>;
/** What the `session` grant admits. */
export declare const SESSION_GRANT_ADMISSION_ACTIONS: Readonly<{
    readonly "oauth.session_grant": Readonly<{
        grade: "use";
    }>;
}>;
/** What the `authorization_code` grant admits, at both of its reads. */
export declare const AUTHORIZATION_CODE_GRANT_ADMISSION_ACTIONS: Readonly<{
    readonly "oauth.code_exchange": Readonly<{
        grade: "use";
    }>;
}>;
/** What the `refresh_token` grant admits. */
export declare const REFRESH_TOKEN_GRANT_ADMISSION_ACTIONS: Readonly<{
    readonly "oauth.refresh": Readonly<{
        grade: "use";
    }>;
}>;
//# sourceMappingURL=admissionActions.d.mts.map