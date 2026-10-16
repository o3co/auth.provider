# verification

Internal module of `device-grant`: the interface the deployment's page calls, where a signed-in user looks up, approves or denies a code.

## Responsibilities
- Enters the session, counts the attempt, decides the code once, and records the decision to `audit`.

## Not here
- The route's declaration and its `csrf` policy (the package's). Issuing tokens (`grant`).

## Offers
- `verificationOver` (the build context) → `verificationWith` (`session`, `rate-limit`'s attempt limit, `audit`, `tokens`' admits, the store interfaces, the runtime, the settings) → the route's handler.

## Depends on
- `session` (entry); `rate-limit` (attempts); `audit` (recording); `tokens` (admits); `token-endpoint` (OAuth error responses); `http` (the request and response, the source); `kernel` (the build context); the package's codes, record and store interfaces
