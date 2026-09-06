export declare function makeValidCoreConfig(): {
    http: {
        port: number;
        trustProxy: false;
    };
    oauth: {
        jwt: {
            signingKey: {
                provider: string;
                local: {
                    algorithm: "HS256";
                    kid: string;
                    secret: string;
                    previousKeys: never[];
                };
            };
        };
        accessToken: {
            expiresIn: number;
        };
        refreshToken: {
            expiresIn: number;
        };
        grants: {};
    };
};
export declare function makeValidFullSections(): {
    session: {
        secret: string;
        maxAge: number;
        secure: true;
        sameSite: "lax";
        domain: null;
        storage: {
            type: string;
        };
    };
    rateLimit: {
        login: {
            windowMs: number;
            limit: number;
        };
    };
    federations: {};
    repositories: {
        client: {
            type: string;
        };
        user: {
            type: string;
        };
        code: {
            type: string;
        };
    };
    endpoints: {
        login: {
            url: string;
        };
    };
    cors: {
        allowedOrigins: never[];
    };
};
export declare function makeValidAppConfig(): {
    session: {
        secret: string;
        maxAge: number;
        secure: true;
        sameSite: "lax";
        domain: null;
        storage: {
            type: string;
        };
    };
    rateLimit: {
        login: {
            windowMs: number;
            limit: number;
        };
    };
    federations: {};
    repositories: {
        client: {
            type: string;
        };
        user: {
            type: string;
        };
        code: {
            type: string;
        };
    };
    endpoints: {
        login: {
            url: string;
        };
    };
    cors: {
        allowedOrigins: never[];
    };
    http: {
        port: number;
        trustProxy: false;
    };
    oauth: {
        jwt: {
            signingKey: {
                provider: string;
                local: {
                    algorithm: "HS256";
                    kid: string;
                    secret: string;
                    previousKeys: never[];
                };
            };
        };
        accessToken: {
            expiresIn: number;
        };
        refreshToken: {
            expiresIn: number;
        };
        grants: {};
    };
};
//# sourceMappingURL=valid-config.d.mts.map