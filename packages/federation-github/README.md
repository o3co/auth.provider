# @o3co/auth-provider-federation-github

GitHub federation provider for `auth.provider`.

```ts
import { createFederationProviderFactory } from "@o3co/auth-provider-session";
import { registerGithubFederation } from "@o3co/auth-provider-federation-github";

const federationProviderFactory = createFederationProviderFactory();
registerGithubFederation(federationProviderFactory);
```
