# Security policy

## Supported versions

Security fixes are released for:

- the latest minor version, in a patch release of it;
- the minor version before it, for three months after the newer minor is released, so that a new minor never forces an upgrade on the day it comes out. This holds before 1.0, and is looked at again at 1.0.

Release candidates are previews and get no fixes of their own: a fix found in one lands in the next. A version past its support is named in the changelog of the release that ends it.

Which surfaces a version keeps compatible, and how a change to them is announced, is in [the release policy](docs/releasing.md#what-a-version-promises).

## Reporting a vulnerability

Report it privately through GitHub: on this repository's **Security** tab, choose **Report a vulnerability**. Do not open a public issue or pull request, or describe it anywhere public, until a fix is released.

Include what you can of:

- the version or commit, and the modules the deployment composes;
- the settings involved, without their secret values;
- what a request or a sequence of requests does, and what you expected instead.

The report stays private between you and the maintainers until it is resolved. Once a fixed version is released, the [changelog](CHANGELOG.md) lists the kind of hole it closes.

## What a report covers

A report is taken for any way a request, a sequence of requests or a deployment that meets the [trust assumptions](docs/security-model.md#trust-assumptions) breaks a guarantee in [the security model](docs/security-model.md), and for any hole no declaration covers.

Not a vulnerability, and only as far as written:

- **The documented consequence of a declared exception the operator chose.** Each is declared where the security model names it ("Declared exceptions", "Left to you", an `accept-*` setting that warns at boot): for example, a request limit that lets requests through uncounted while its store is down under `rate-limit.fail-mode = open`. Only that documented consequence is out: a failure the setting does not explain is still a vulnerability.
- **What follows from a deployment breaking a trust assumption**, for what that assumption protects: a proxy that passes on a client's `X-Forwarded-For`, say, lets clients choose their source.

Still reportable, though no guarantee names them:

- Leaks through timing, such as an answer that tells a client id, an account or a key apart by how long it takes.
- Failures an outside party can cause: a `503` that fails closed keeps a guarantee, but a way to make the provider answer it to others is a report.

Which versions get fixes is [Supported versions](#supported-versions), as it stands when a fix is published; a report against a version outside it is still welcome, and is answered as the policy says.

