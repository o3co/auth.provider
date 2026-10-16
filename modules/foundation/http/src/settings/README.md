# settings

Internal module of `http`: the schema of `http`'s operator section.

## Responsibilities
- Decides which settings boot, and says what each means in its description (the settings list).

## Not here
- The trusted proxies and hops (`request-source`'s `sourceSettings`) and where the client's certificate is forwarded (`client-certificate`'s `certificateSettings`): the section takes their parts under its own keys.
- What the settings drive: listening, a request's source, cookies, cross-origin answers.

## Offers
- The section's schema, each key described.

## Depends on
- `zod`, `request-source`, `client-certificate`.
