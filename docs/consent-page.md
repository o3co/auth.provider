# Your consent page

The provider has no consent screen of its own. When a client that is not first-party asks for scopes the user has not agreed to for it, or asks with `prompt=consent`, the authorization endpoint sends the browser to the page you set as `consent.page`, adding `challenge`: the pending consent the page shows and answers. Your page reads what is asked, shows it to the user, and posts the user's decision back.

Without `consent.page`, nobody is asked: a client that is not first-party is refused `unauthorized_client`. A client you run yourself needs no page; register it with `first-party = true` in its `consent` section (the `consent` card).

## Where the page is served

Serve the page from the provider's public origin (`http.public-origin`), as [your login page](login-page.md#where-the-page-is-served) is: it reads the pending consent with the session's cookie, and its post is refused unless it carries same-origin evidence (an `Origin` that is the public origin) or the double-submit token. Set `consent.page` to the page's https URL.

## 1. Read what is asked

```http
GET /oauth/consent?challenge=<the challenge your page received>
```

The browser sends the session's cookie with it. `200`, never cached:

```json
{
  "client_id": "app",
  "client_name": "Acme",
  "client_uri": "https://acme.example/about",
  "scopes": ["read", "write"],
  "granted_scopes": [],
  "expires_in": 600
}
```

- `scopes`: what the client asks now. `granted_scopes`: what the user already agreed to for this client, which the page may show as kept.
- `client_name` and `client_uri` are there when the client's registration sets them (its `consent` section's `name` and `uri`). A client whose registration is a document it published (`clients-cimd`) also has `client_id_host`, the host its document was read from: show it, since the name is the client's own word.
- `expires_in`: seconds left to answer (`consent.challenge-lifetime`, 10 minutes unless set).
- Write every value into the page as text, never as markup: the name and the URI are the client's.

| Answer | What the page does |
|---|---|
| `200` | Show the client and the scopes, and ask the user. |
| `401 {"error": "no_session"}` | The browser holds no session: the user signed out or it expired. Say so; the client can start again. |
| `400 {"error": "unknown_challenge"}` | The challenge is unknown, expired, already answered, or another session's. Say so; the client can start again. |
| `503 {"error": "temporarily_unavailable"}` | Try again later. |

## 2. Post the decision

```http
POST /oauth/consent
Content-Type: application/x-www-form-urlencoded

challenge=<the challenge>&decision=accept&csrf_token=<csrf_token>
```

- `decision` is `accept` or `deny`. The body is a form or JSON. Send each parameter once.
- The CSRF token comes from `GET /session/csrf` ([your login page](login-page.md#1-get-a-csrf-token)), in the form under its `body_field` or in the header it names. A form posted from the public origin carries same-origin evidence too, but send the token for a browser that leaves out `Origin`.

| Answer | What the page does |
|---|---|
| `303` | Nothing: the browser follows it back to the authorization endpoint, which goes on to the client with a code, or with `access_denied` after a denial. Post as a form navigation, so the browser follows it. |
| `400 {"error": "unknown_challenge"}` | As above. Sending the other decision for an answered challenge gets this too. |
| `400` `invalid_decision` or `repeated_parameter` | The request is malformed: fix the page. The challenge stays usable. |
| `403 {"error": "csrf"}` | Get a new token, then post again. The challenge stays usable. |
| `503 {"error": "temporarily_unavailable"}` | Post the same decision again: it is the only way to recover, and the same decision sent again gets the same answer. |

An accepted consent is kept for the user and client, so the client is not asked again for the same scopes. A denial keeps nothing.

## An example page

A whole page, served at `consent.page` on the public origin. It asks nothing of a framework and writes the client's words as text only.

```html
<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>Allow access</title>
<main>
  <p id="message">Loading…</p>
  <form id="decide" method="post" action="/oauth/consent" hidden>
    <p><strong id="client"></strong> asks to:</p>
    <ul id="scopes"></ul>
    <input type="hidden" name="challenge">
    <input type="hidden" name="csrf_token">
    <button name="decision" value="accept">Allow</button>
    <button name="decision" value="deny">Deny</button>
  </form>
</main>
<script type="module">
  const challenge = new URL(location.href).searchParams.get("challenge") ?? "";
  const message = document.getElementById("message");
  const [asked, csrf] = await Promise.all([
    fetch(`/oauth/consent?challenge=${encodeURIComponent(challenge)}`),
    fetch("/session/csrf").then((r) => r.json()),
  ]);
  if (asked.status !== 200) {
    message.textContent =
      asked.status === 503 ? "Try again in a moment." : "This request has ended. Go back to the app and try again.";
  } else {
    const body = await asked.json();
    const form = document.getElementById("decide");
    document.getElementById("client").textContent =
      body.client_id_host ? `${body.client_name ?? body.client_id} (${body.client_id_host})` : (body.client_name ?? body.client_id);
    for (const scope of body.scopes) {
      const item = document.createElement("li");
      item.textContent = scope; // Describe each scope in your own words here.
      document.getElementById("scopes").append(item);
    }
    form.elements.challenge.value = challenge;
    form.elements[csrf.body_field].value = csrf.csrf_token;
    message.hidden = true;
    form.hidden = false;
  }
</script>
</html>
```

## Related

- Each setting named here is in the [configuration reference](configuration.md): `consent.page`, `consent.challenge-lifetime`, and a client's `consent` section.
- The `consent` card holds the full contract, under `modules/oauth/` in the repository; `authorize`'s says when a consent is asked.
