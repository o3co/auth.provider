# @o3co/auth-provider-federation-google

Google federation provider for `auth.provider`.

```ts
import { createFederationProviderFactory } from "@o3co/auth-provider-session";
import { registerGoogleFederation } from "@o3co/auth-provider-federation-google";

const federationProviderFactory = createFederationProviderFactory();
registerGoogleFederation(federationProviderFactory);
```
