"""The Authlib adapter: one flow per run, told on its first input line, done with Authlib's own calls
(its requests session); each browser step is asked of the driver, and the result is what Authlib gave
back. It trusts the front's certificate its instruction gives, and nothing else."""

import json
import os
import secrets
import sys
import tempfile
import traceback

from authlib.integrations.requests_client import OAuth2Session, OAuthError
from authlib.jose import JsonWebKey, jwt
from authlib.oauth2.rfc7523 import PrivateKeyJWT
from authlib.oidc.core import CodeIDToken
from joserfc.jwk import ECKey


def write(value):
    print(json.dumps(value), flush=True)


def ask(question):
    write(question)
    return json.loads(sys.stdin.readline())


class Refused(Exception):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


class Run:
    def __init__(self, given):
        self.given = given
        self.client = given["client"]
        # The one certificate trusted: requests' verify takes a bundle of it alone.
        bundle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
        bundle.write(given["ca"])
        bundle.close()
        self.ca = bundle.name
        self.metadata = self.discovered()

    def discovered(self):
        """The provider's discovery, refused where it names an endpoint or key set over anything but https."""
        import requests

        url = self.given["issuer"].rstrip("/") + "/.well-known/openid-configuration"
        metadata = requests.get(url, verify=self.ca, timeout=30).json()
        for key, value in metadata.items():
            if (key.endswith("_endpoint") or key == "jwks_uri") and isinstance(value, str) and not value.startswith("https://"):
                raise Refused("insecure", f"the discovery names {key} {value}, not https")
        return metadata

    def session(self, **more):
        method = self.client["method"]
        session = OAuth2Session(
            client_id=self.client["id"],
            client_secret=self.client.get("secret"),
            scope=self.given.get("scope", "openid"),
            redirect_uri=self.given.get("redirectUri"),
            token_endpoint_auth_method=method,
            # Unset, Authlib authenticates revocation and introspection by Basic, whatever the client's method.
            revocation_endpoint_auth_method=method,
            code_challenge_method="S256",
            **more,
        )
        session.verify = self.ca
        return session

    def resource(self):
        resource = self.given.get("resource")
        return {"resource": resource} if resource else {}

    def sign_in(self, session):
        """The code flow with PKCE, state and nonce; the ID token checked as Authlib's OpenID claims check it."""
        verifier = secrets.token_urlsafe(48)
        nonce = secrets.token_urlsafe(24)
        url, state = session.create_authorization_url(
            self.metadata["authorization_endpoint"], code_verifier=verifier, nonce=nonce, **self.resource()
        )
        location = ask({"ask": "browse", "url": url})["location"]
        token = session.fetch_token(
            self.metadata["token_endpoint"],
            authorization_response=location,
            state=state,
            code_verifier=verifier,
            **self.resource(),
        )
        keys = JsonWebKey.import_key_set(session.get(self.metadata["jwks_uri"]).json())
        claims = jwt.decode(
            token["id_token"],
            keys,
            claims_cls=CodeIDToken,
            claims_options={"iss": {"essential": True, "value": self.given["issuer"]}},
            claims_params={"nonce": nonce, "client_id": self.client["id"]},
        )
        claims.validate(leeway=60)
        return token, dict(claims)

    def login(self):
        session = self.session()
        token, claims = self.sign_in(session)
        userinfo = session.get(self.metadata["userinfo_endpoint"]).json()
        return {
            "idToken": claims,
            "userinfo": userinfo,
            "tokenType": token.get("token_type"),
            "scope": token.get("scope"),
            "refreshToken": "refresh_token" in token,
        }

    def refresh(self):
        session = self.session()
        token, _ = self.sign_in(session)
        first = token.get("refresh_token")
        if not first:
            raise Refused("no_refresh_token", "the code's token answer held no refresh token")
        renewed = session.refresh_token(self.metadata["token_endpoint"], refresh_token=first)
        try:
            session.refresh_token(self.metadata["token_endpoint"], refresh_token=first)
            replayed = "taken"
        except OAuthError as error:
            replayed = error.error or "refused"
        return {
            "accessToken": "access_token" in renewed,
            "rotated": bool(renewed.get("refresh_token")) and renewed.get("refresh_token") != first,
            "replayed": replayed,
        }

    def resource_flow(self):
        token, _ = self.sign_in(self.session())
        return {"accessToken": token["access_token"]}

    def client_credentials(self):
        """The client credentials grant; a private key JWT names the issuer as its audience where told so."""
        if self.client["method"] == "private_key_jwt":
            session = self.session()
            # PrivateKeyJWT takes a key that is no key object for RSA, so an EC key goes as one.
            session.client_secret = ECKey.import_key(self.client["privateJwk"])
            audience = self.given["issuer"] if self.given.get("assertionAudience") == "issuer" else self.metadata["token_endpoint"]
            session.register_client_auth_method(PrivateKeyJWT(audience, alg="ES256"))
        else:
            session = self.session()
        token = session.fetch_token(
            self.metadata["token_endpoint"], grant_type="client_credentials", **self.resource()
        )
        return {"accessToken": token["access_token"], "tokenType": token.get("token_type")}

    def revocation(self):
        session = self.session()
        token, _ = self.sign_in(session)
        access = token["access_token"]
        before = session.introspect_token(self.metadata["introspection_endpoint"], token=access).json()
        revoked = session.revoke_token(self.metadata["revocation_endpoint"], token=access, token_type_hint="access_token")
        if revoked.status_code != 200:
            raise Refused("revocation", f"{revoked.status_code}: {revoked.text[:200]}")
        after = session.introspect_token(self.metadata["introspection_endpoint"], token=access).json()
        return {"before": before.get("active"), "after": after.get("active")}


def main():
    given = json.loads(sys.stdin.readline())
    try:
        run = Run(given)
        flows = {
            "login": run.login,
            "public-login": run.login,
            "cimd": run.login,
            "refresh": run.refresh,
            "resource": run.resource_flow,
            "client-credentials": run.client_credentials,
            "client-credentials-secret": run.client_credentials,
            "revocation": run.revocation,
        }
        flow = flows.get(given["flow"])
        if flow is None:
            raise Refused("unsupported", "no flow " + given["flow"])
        write({"result": flow()})
    except Refused as refused:
        write({"error": {"type": refused.kind, "message": str(refused)}})
    except OAuthError as error:
        write({"error": {"type": error.error or "OAuthError", "message": str(error)}})
    except Exception as error:  # noqa: BLE001 - every other failure is reported as the library raised it
        # Where it was raised goes to the error stream, the dialog's diagnostics.
        traceback.print_exc()
        write({"error": {"type": type(error).__name__, "message": str(error)}})
    sys.stdout.flush()
    os._exit(0)


main()
