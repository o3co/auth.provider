# @o3co/auth-provider-federation-github

GitHub federation provider for `auth.provider`.

## Usage

Add `githubFederationModule` to the manifest list passed to `createApp`. A small
config-bootstrap module supplies the typed `githubFederationConfig` slot (per
A5 §10.1 const-Module pattern).

```ts
import { createApp, defineModule } from "@o3co/auth-provider-core";
import { extractFederationSection, sessionModule } from "@o3co/auth-provider-session";
import {
  githubFederationModule,
  type GithubProviderConfig,
} from "@o3co/auth-provider-federation-github";

const githubConfigBridgeModule = defineModule({
  name: "github-federation-config",
  requires: ["config"] as const,
  provides: {
    githubFederationConfig: (deps): GithubProviderConfig => {
      const slice = extractFederationSection(deps.config.federations, "github");
      if (!slice) throw new Error("federations.github must be enabled");
      return {
        name: "github",
        clientId: slice.clientId as string,
        clientSecret: slice.clientSecret as string,
        callbackURL: slice.callbackURL as string,
      };
    },
  },
});

const handle = await createApp({
  modules: [
    sessionModule,
    githubFederationModule,
    githubConfigBridgeModule,
    // ... composition-root modules supplying userRepository + four-store split
  ],
  bootstrapComponents: { config, pathResolver },
});
```

For advanced or multi-tenant setups, call `createGithubProvider(config)`
directly and wrap with a custom `defineModule(...)` factory per
A2-α §7.1.

## Public API

- `githubFederationModule` — const Module contributing `federations.github` +
  `federationRedirectPolicies.github`
- `createGithubProvider(config: GithubProviderConfig): GithubProvider` —
  pure constructor (advanced / multi-tenant use)
- `GithubProviderConfig`, `GithubProvider` — types
- `githubFederationConfig` — declared ComponentMap slot for the config bridge
