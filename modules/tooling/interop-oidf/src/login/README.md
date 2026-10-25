# login

Internal module of `interop-oidf`: the deployment's login page, as the suite's browser meets it.

## Offers
- `loginPage`: a form of named fields with no script, carrying `redirect_to`; its answer taken to the provider's `POST /session/login` as the browser (its cookie and address, the public origin as `Origin`), and turned into a `302` to the `redirect_to` the provider gives, with the cookies it set.

## Invariants
- A refused login shows the form again with the provider's error; a login with nowhere to go says it is done; a provider that does not answer within its time is a `504` saying so.
- Values in the page are escaped.
