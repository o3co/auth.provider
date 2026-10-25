package interop;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenRevocationRequest;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.JWTBearerGrant;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetails;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionFactory;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.tokenexchange.TokenExchangeGrant;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationRequest;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationResponse;
import com.nimbusds.oauth2.sdk.device.DeviceCodeGrant;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * The Nimbus adapter: one flow per run, told on its first input line, done with the library's own
 * classes; each browser step is asked of the driver, and the result is what the library gave back.
 * It trusts the front's certificate as the instruction gives it, and nothing else.
 */
public final class Main {
  private static final BufferedReader IN =
      new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

  private static Map<String, Object> read() throws Exception {
    return JSONObjectUtils.parse(IN.readLine());
  }

  private static void write(Map<String, Object> value) {
    System.out.println(JSONObjectUtils.toJSONString(value));
    System.out.flush();
  }

  private static String orElse(Map<String, Object> from, String key, String otherwise) {
    Object value = from.get(key);
    return value instanceof String s ? s : otherwise;
  }

  private static Map<String, Object> ask(Map<String, Object> question) throws Exception {
    write(question);
    return read();
  }

  /** A failure the adapter reports as the library or the provider named it. */
  static final class Refused extends RuntimeException {
    final String type;

    Refused(String type, String message) {
      super(message);
      this.type = type;
    }

    static Refused of(ErrorObject error) {
      return new Refused(
          String.valueOf(error.getCode()),
          error.getHTTPStatusCode() + ": " + error.getDescription());
    }
  }

  private final Map<String, Object> instruction;
  private final SSLSocketFactory tls;
  /** The DPoP proofs, in the DPoP flow alone. */
  private DefaultDPoPProofFactory dpop;

  private Main(Map<String, Object> instruction) throws Exception {
    this.instruction = instruction;
    this.tls = trusting(JSONObjectUtils.getString(instruction, "ca"));
  }

  private static SSLSocketFactory trusting(String pem) throws Exception {
    KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
    store.load(null, null);
    store.setCertificateEntry(
        "front",
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII))));
    TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trust.init(store);
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, trust.getTrustManagers(), null);
    return context.getSocketFactory();
  }

  /** A request over https alone, trusting the front's certificate; any other URL is refused before it is sent. */
  private HTTPRequest sending(HTTPRequest request) {
    if (!"https".equals(request.getURI().getScheme()))
      throw new Refused("insecure", "a request to " + request.getURI() + ", not https");
    request.setSSLSocketFactory(tls);
    return request;
  }

  /** An endpoint or key set the discovery names over anything but https fails the flow before any request. */
  private static void refuseInsecure(Map<String, Object> metadata) throws Refused {
    for (Map.Entry<String, Object> e : metadata.entrySet()) {
      String key = e.getKey();
      if (!(key.endsWith("_endpoint") || key.equals("jwks_uri")) || !(e.getValue() instanceof String value)) continue;
      if (!value.startsWith("https://"))
        throw new Refused("insecure", "the discovery names " + key + " " + value + ", not https");
    }
  }

  private Map<String, Object> client() throws Exception {
    return JSONObjectUtils.getJSONObject(instruction, "client");
  }

  /** The client's authentication at the token endpoint, which a private key JWT names as its audience. */
  private ClientAuthentication authentication(URI tokenEndpoint) throws Exception {
    Map<String, Object> c = client();
    ClientID id = new ClientID(JSONObjectUtils.getString(c, "id"));
    String method = JSONObjectUtils.getString(c, "method");
    Secret secret = new Secret(orElse(c, "secret", ""));
    if ("client_secret_basic".equals(method)) return new ClientSecretBasic(id, secret);
    if ("client_secret_post".equals(method)) return new ClientSecretPost(id, secret);
    if ("private_key_jwt".equals(method)) {
      ECKey key = ECKey.parse(JSONObjectUtils.getJSONObject(c, "privateJwk"));
      // The library's own default names the token endpoint; told so, the assertion names the issuer.
      if ("issuer".equals(instruction.get("assertionAudience")))
        return new PrivateKeyJWT(
            new JWTAuthenticationClaimsSet(
                id, new Audience(JSONObjectUtils.getString(instruction, "issuer"))),
            JWSAlgorithm.ES256,
            key.toECPrivateKey(),
            key.getKeyID(),
            null);
      return new PrivateKeyJWT(
          id, tokenEndpoint, JWSAlgorithm.ES256, key.toECPrivateKey(), key.getKeyID(), null);
    }
    if ("none".equals(method)) return null;
    throw new Refused("unsupported", "no client authentication " + method);
  }

  private URI resource() {
    Object r = instruction.get("resource");
    return r instanceof String s ? URI.create(s) : null;
  }

  /** A token request with the client's authentication, or its id alone for a public client, for the resource asked. */
  private TokenRequest tokenRequest(URI endpoint, AuthorizationGrant grant) throws Exception {
    ClientAuthentication auth = authentication(endpoint);
    TokenRequest.Builder builder =
        auth != null
            ? new TokenRequest.Builder(endpoint, auth, grant)
            : new TokenRequest.Builder(endpoint, new ClientID(JSONObjectUtils.getString(client(), "id")), grant);
    if (resource() != null) builder.resources(resource());
    Object scope = instruction.get("scope");
    if (grant instanceof ClientCredentialsGrant && scope instanceof String s) builder.scope(Scope.parse(s));
    return builder.build();
  }

  /** Signs in asking for a token for one resource server, by the parameter in both requests. */
  private Map<String, Object> resourceFlow() throws Exception {
    SignedIn in = signIn();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("accessToken", in.tokens().getOIDCTokens().getAccessToken().getValue());
    return result;
  }

  /** The client credentials grant, the client authenticating as its configuration says. */
  private Map<String, Object> clientCredentials() throws Exception {
    OIDCProviderMetadata op = provider();
    TokenResponse answer =
        TokenResponse.parse(
            sending(tokenRequest(op.getTokenEndpointURI(), new ClientCredentialsGrant()).toHTTPRequest())
                .send());
    if (!answer.indicatesSuccess()) throw Refused.of(answer.toErrorResponse().getErrorObject());
    AccessToken token = answer.toSuccessResponse().getTokens().getAccessToken();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("accessToken", token.getValue());
    result.put("tokenType", token.getType().getValue());
    result.put("scope", token.getScope() == null ? null : token.getScope().toString());
    return result;
  }

  private boolean active(OIDCProviderMetadata op, AccessToken token) throws Exception {
    TokenIntrospectionResponse told =
        TokenIntrospectionResponse.parse(
            sending(
                    new TokenIntrospectionRequest(
                            op.getIntrospectionEndpointURI(),
                            authentication(op.getTokenEndpointURI()),
                            token)
                        .toHTTPRequest())
                .send());
    if (!told.indicatesSuccess()) throw Refused.of(told.toErrorResponse().getErrorObject());
    return told.toSuccessResponse().isActive();
  }

  /** Signs in, introspects the access token, revokes it, and introspects it again. */
  private Map<String, Object> revocation() throws Exception {
    SignedIn in = signIn();
    AccessToken token = in.tokens().getOIDCTokens().getAccessToken();
    boolean before = active(in.op(), token);
    var revoked =
        sending(
                new TokenRevocationRequest(
                        in.op().getRevocationEndpointURI(),
                        authentication(in.op().getTokenEndpointURI()),
                        token)
                    .toHTTPRequest())
            .send();
    if (revoked.getStatusCode() != 200)
      throw new Refused("revocation", revoked.getStatusCode() + ": " + revoked.getContent());
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("before", before);
    result.put("after", active(in.op(), token));
    return result;
  }

  private OIDCProviderMetadata provider() throws Exception {
    OIDCProviderMetadata op =
        OIDCProviderMetadata.resolve(
            new Issuer(JSONObjectUtils.getString(instruction, "issuer")), this::sending);
    refuseInsecure(op.toJSONObject());
    return op;
  }

  /** The provider's OAuth metadata (RFC 8414), for a provider that is no OpenID one, held to https alike. */
  private AuthorizationServerMetadata server() throws Exception {
    AuthorizationServerMetadata as =
        AuthorizationServerMetadata.resolve(
            new Issuer(JSONObjectUtils.getString(instruction, "issuer")), this::sending);
    refuseInsecure(as.toJSONObject());
    return as;
  }

  /** Signs in, then exchanges the access token for another (RFC 8693), the client authenticated. */
  private Map<String, Object> tokenExchange() throws Exception {
    SignedIn in = signIn();
    AccessToken subject = in.tokens().getOIDCTokens().getAccessToken();
    TokenRequest request =
        new TokenRequest(
            in.op().getTokenEndpointURI(),
            authentication(in.op().getTokenEndpointURI()),
            new TokenExchangeGrant(subject, TokenTypeURI.ACCESS_TOKEN));
    TokenResponse answer = TokenResponse.parse(sending(request.toHTTPRequest()).send());
    if (!answer.indicatesSuccess()) throw Refused.of(answer.toErrorResponse().getErrorObject());
    var success = answer.toSuccessResponse();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("accessToken", success.getTokens().getAccessToken().getValue());
    TokenTypeURI issued = success.getTokens().getAccessToken().getIssuedTokenType();
    result.put("issuedTokenType", issued == null ? null : issued.getURI().toString());
    result.put("sub", in.claims().getSubject().getValue());
    return result;
  }

  /** The jwt-bearer grant: an assertion an issuer the provider trusts signs, built by Nimbus, the client authenticated. */
  private Map<String, Object> jwtBearer() throws Exception {
    AuthorizationServerMetadata as = server();
    Map<String, Object> signer = JSONObjectUtils.getJSONObject(instruction, "assertionIssuer");
    ECKey key = ECKey.parse(JSONObjectUtils.getJSONObject(signer, "privateJwk"));
    SignedJWT assertion =
        JWTAssertionFactory.create(
            new JWTAssertionDetails(
                new Issuer(JSONObjectUtils.getString(signer, "issuer")),
                new Subject(JSONObjectUtils.getString(instruction, "subject")),
                new Audience(as.getIssuer().getValue())),
            JWSAlgorithm.ES256,
            key.toECPrivateKey(),
            key.getKeyID(),
            null);
    TokenRequest request =
        new TokenRequest.Builder(
                as.getTokenEndpointURI(),
                authentication(as.getTokenEndpointURI()),
                new JWTBearerGrant(assertion))
            .scope(Scope.parse(orElse(instruction, "scope", "read")))
            .build();
    TokenResponse answer = TokenResponse.parse(sending(request.toHTTPRequest()).send());
    if (!answer.indicatesSuccess()) throw Refused.of(answer.toErrorResponse().getErrorObject());
    AccessToken token = answer.toSuccessResponse().getTokens().getAccessToken();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("accessToken", token.getValue());
    result.put("tokenType", token.getType().getValue());
    return result;
  }

  /** What a sign-in gave: the provider, the tokens and the ID token's claims as the validator took them. */
  record SignedIn(OIDCProviderMetadata op, OIDCTokenResponse tokens, IDTokenClaimsSet claims) {}

  private Map<String, Object> login() throws Exception {
    SignedIn in = signIn();
    BearerAccessToken access = in.tokens().getOIDCTokens().getBearerAccessToken();
    var info =
        UserInfoResponse.parse(
            sending(new UserInfoRequest(in.op().getUserInfoEndpointURI(), access).toHTTPRequest()).send());
    if (!info.indicatesSuccess()) throw Refused.of(info.toErrorResponse().getErrorObject());
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("idToken", in.claims().toJSONObject());
    result.put("userinfo", info.toSuccessResponse().getUserInfo().toJSONObject());
    result.put("tokenType", access.getType().getValue());
    result.put("scope", access.getScope() == null ? null : access.getScope().toString());
    result.put("refreshToken", in.tokens().getOIDCTokens().getRefreshToken() != null);
    return result;
  }

  private TokenResponse refreshing(OIDCProviderMetadata op, RefreshToken token) throws Exception {
    return TokenResponse.parse(
        sending(tokenRequest(op.getTokenEndpointURI(), new RefreshTokenGrant(token)).toHTTPRequest()).send());
  }

  /** Signs in, refreshes once, then presents the refresh token it replaced again. */
  private Map<String, Object> refresh() throws Exception {
    SignedIn in = signIn();
    RefreshToken first = in.tokens().getOIDCTokens().getRefreshToken();
    if (first == null) throw new Refused("no_refresh_token", "the code's token answer held no refresh token");
    TokenResponse renewed = refreshing(in.op(), first);
    if (!renewed.indicatesSuccess()) throw Refused.of(renewed.toErrorResponse().getErrorObject());
    var tokens = renewed.toSuccessResponse().getTokens();
    TokenResponse replayed = refreshing(in.op(), first);
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("accessToken", tokens.getAccessToken() != null);
    result.put("rotated", tokens.getRefreshToken() != null && !tokens.getRefreshToken().equals(first));
    result.put(
        "replayed",
        replayed.indicatesSuccess()
            ? "taken"
            : String.valueOf(replayed.toErrorResponse().getErrorObject().getCode()));
    return result;
  }

  private SignedIn signIn() throws Exception {
    OIDCProviderMetadata op = provider();
    ClientID id = new ClientID(JSONObjectUtils.getString(client(), "id"));
    URI redirect = URI.create(JSONObjectUtils.getString(instruction, "redirectUri"));
    CodeVerifier verifier = new CodeVerifier();
    State state = new State();
    Nonce nonce = new Nonce();
    AuthenticationRequest request =
        new AuthenticationRequest.Builder(
                new ResponseType("code"),
                Scope.parse(orElse(instruction, "scope", "openid")),
                id,
                redirect)
            .endpointURI(op.getAuthorizationEndpointURI())
            .state(state)
            .nonce(nonce)
            .codeChallenge(verifier, CodeChallengeMethod.S256)
            .resources(resource() == null ? null : new URI[] {resource()})
            .build();
    Map<String, Object> question = new LinkedHashMap<>();
    question.put("ask", "browse");
    question.put("url", request.toURI().toString());
    String location = JSONObjectUtils.getString(ask(question), "location");
    AuthenticationResponse answer = AuthenticationResponseParser.parse(URI.create(location));
    if (!answer.indicatesSuccess()) throw Refused.of(answer.toErrorResponse().getErrorObject());
    if (!state.equals(answer.getState())) throw new Refused("state", "the answer's state is not the request's");
    // RFC 9207: the answer names the provider the request went to.
    if (answer.getIssuer() != null && !answer.getIssuer().equals(op.getIssuer()))
      throw new Refused("iss", "the answer's iss is " + answer.getIssuer());
    AuthorizationCode code = answer.toSuccessResponse().getAuthorizationCode();
    TokenRequest token =
        tokenRequest(op.getTokenEndpointURI(), new AuthorizationCodeGrant(code, redirect, verifier));
    var tokenAnswer = OIDCTokenResponse.parse(proven(sending(token.toHTTPRequest()), null));
    if (!tokenAnswer.indicatesSuccess()) throw Refused.of(tokenAnswer.toErrorResponse().getErrorObject());
    OIDCTokenResponse tokens = (OIDCTokenResponse) tokenAnswer.toSuccessResponse();
    JWT idToken = tokens.getOIDCTokens().getIDToken();
    var keys = new DefaultResourceRetriever(5000, 5000, 512 * 1024, true, tls);
    IDTokenValidator validator =
        new IDTokenValidator(op.getIssuer(), id, JWSAlgorithm.RS256, op.getJWKSetURI().toURL(), keys);
    return new SignedIn(op, tokens, validator.validate(idToken, nonce));
  }

  /**
   * Sends the request, with a DPoP proof in the DPoP flow (bound to the access token at a resource),
   * and once more with the nonce the server asked for, as the client must by hand in Nimbus.
   */
  private HTTPResponse proven(HTTPRequest request, AccessToken token) throws Exception {
    if (dpop == null) return request.send();
    Nonce nonce = null;
    for (int attempt = 0; ; attempt++) {
      String htm = request.getMethod().name();
      request.setDPoP(
          token == null
              ? dpop.createDPoPJWT(htm, request.getURI(), nonce)
              : dpop.createDPoPJWT(htm, request.getURI(), token, nonce));
      HTTPResponse response = request.send();
      boolean asked = (response.getStatusCode() == 400 || response.getStatusCode() == 401) && response.getDPoPNonce() != null;
      if (!asked || attempt > 0) return response;
      nonce = response.getDPoPNonce();
    }
  }

  /** Signs in with the access token bound to a DPoP key, and reads userinfo with it, answering each nonce asked. */
  private Map<String, Object> dpopFlow() throws Exception {
    dpop =
        new DefaultDPoPProofFactory(
            new ECKeyGenerator(Curve.P_256).keyID("dpop").generate(), JWSAlgorithm.ES256);
    SignedIn in = signIn();
    AccessToken token = in.tokens().getOIDCTokens().getAccessToken();
    if (!(token instanceof DPoPAccessToken bound))
      throw new Refused("not_dpop", "the access token is of type " + token.getType());
    var info =
        UserInfoResponse.parse(
            proven(sending(new UserInfoRequest(in.op().getUserInfoEndpointURI(), bound).toHTTPRequest()), bound));
    if (!info.indicatesSuccess()) throw Refused.of(info.toErrorResponse().getErrorObject());
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("tokenType", token.getType().getValue());
    result.put("accessToken", token.getValue());
    result.put("sub", in.claims().getSubject().getValue());
    result.put("userinfo", info.toSuccessResponse().getUserInfo().toJSONObject());
    return result;
  }

  /** The device authorization grant: the user code is approved by the driver as the user, then polled for. */
  private Map<String, Object> device() throws Exception {
    OIDCProviderMetadata op = provider();
    ClientAuthentication auth = authentication(op.getTokenEndpointURI());
    var started =
        DeviceAuthorizationResponse.parse(
            sending(
                    new DeviceAuthorizationRequest.Builder(auth)
                        .endpointURI(op.getDeviceAuthorizationEndpointURI())
                        .scope(Scope.parse(orElse(instruction, "scope", "openid")))
                        .build()
                        .toHTTPRequest())
                .send());
    if (!started.indicatesSuccess()) throw Refused.of(started.toErrorResponse().getErrorObject());
    var codes = started.toSuccessResponse();
    Map<String, Object> question = new LinkedHashMap<>();
    question.put("ask", "device");
    question.put("userCode", codes.getUserCode().getValue());
    question.put("verificationUri", codes.getVerificationURI().toString());
    ask(question);
    long interval = Math.max(codes.getInterval(), 1);
    for (int attempt = 0; attempt < 30; attempt++) {
      TokenResponse answer =
          TokenResponse.parse(
              sending(
                      new TokenRequest(
                              op.getTokenEndpointURI(), auth, new DeviceCodeGrant(codes.getDeviceCode()))
                          .toHTTPRequest())
                  .send());
      if (answer.indicatesSuccess()) {
        AccessToken token = answer.toSuccessResponse().getTokens().getAccessToken();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("accessToken", token.getValue());
        result.put("tokenType", token.getType().getValue());
        return result;
      }
      String code = answer.toErrorResponse().getErrorObject().getCode();
      if ("slow_down".equals(code)) interval += 5;
      else if (!"authorization_pending".equals(code)) throw Refused.of(answer.toErrorResponse().getErrorObject());
      Thread.sleep(interval * 1000);
    }
    throw new Refused("timeout", "the device was not approved in time");
  }

  /** Signs in, then ends the session by the provider's end-session endpoint, as the relying party starts it. */
  private Map<String, Object> logout() throws Exception {
    SignedIn in = signIn();
    State state = new State();
    URI url =
        new LogoutRequest(
                in.op().getEndSessionEndpointURI(),
                in.tokens().getOIDCTokens().getIDToken(),
                URI.create(JSONObjectUtils.getString(instruction, "postLogoutRedirectUri")),
                state)
            .toURI();
    Map<String, Object> question = new LinkedHashMap<>();
    question.put("ask", "logout");
    question.put("url", url.toString());
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("location", JSONObjectUtils.getString(ask(question), "location"));
    result.put("state", state.getValue());
    return result;
  }

  public static void main(String[] args) throws Exception {
    Map<String, Object> instruction = read();
    Map<String, Object> out = new LinkedHashMap<>();
    try {
      Main main = new Main(instruction);
      String flow = JSONObjectUtils.getString(instruction, "flow");
      out.put(
          "result",
          switch (flow) {
            case "login", "public-login" -> main.login();
            case "refresh" -> main.refresh();
            case "resource" -> main.resourceFlow();
            case "client-credentials" -> main.clientCredentials();
            case "revocation" -> main.revocation();
            case "dpop" -> main.dpopFlow();
            case "device" -> main.device();
            case "logout" -> main.logout();
            case "jwt-bearer" -> main.jwtBearer();
            case "token-exchange" -> main.tokenExchange();
            default -> throw new Refused("unsupported", "no flow " + flow);
          });
    } catch (Refused refused) {
      out.put("error", Map.of("type", refused.type, "message", String.valueOf(refused.getMessage())));
    } catch (Exception failure) {
      out.put(
          "error",
          Map.of("type", failure.getClass().getSimpleName(), "message", String.valueOf(failure.getMessage())));
    }
    write(out);
    System.exit(0);
  }
}
