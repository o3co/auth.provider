package interop;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.client.JwtBearerOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.TokenExchangeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.RestClientJwtBearerTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientTokenExchangeTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestClient;

/**
 * The Spring Security adapter: one flow per run, told on its first input line, done with Spring
 * Security's OAuth2 client providers, headless; it asks the driver nothing, and the result is what
 * Spring gave back. It trusts the front's certificate its instruction gives, and nothing else.
 */
public final class Main {
  /** A failure the adapter reports as Spring or the provider named it. */
  static final class Refused extends RuntimeException {
    final String type;

    Refused(String type, String message) {
      super(message);
      this.type = type;
    }
  }

  private final Map<String, Object> instruction;
  private final SSLContext tls;
  private final RestClient rest;

  private Main(Map<String, Object> instruction) throws Exception {
    this.instruction = instruction;
    this.tls = trusting(JSONObjectUtils.getString(instruction, "ca"));
    // The converters and error handler Spring's own token response clients use, over the one trusted connection.
    this.rest =
        RestClient.builder()
            .requestFactory(new JdkClientHttpRequestFactory(HttpClient.newBuilder().sslContext(tls).build()))
            .messageConverters(
                converters -> {
                  converters.clear();
                  converters.add(new FormHttpMessageConverter());
                  converters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
                })
            .defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
            .build();
  }

  private static SSLContext trusting(String pem) throws Exception {
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
    return context;
  }

  /**
   * The provider's token endpoint, from its metadata (Spring's discovery takes no trust store of its
   * own, and these grants need nothing else of it); one that is not https is refused.
   */
  private String tokenEndpoint() throws Exception {
    String issuer = JSONObjectUtils.getString(instruction, "issuer");
    // An OpenID provider's discovery, or the OAuth metadata (RFC 8414) where the instruction names it.
    String where = String.valueOf(instruction.getOrDefault("metadata", "openid-configuration"));
    HttpResponse<String> answer =
        HttpClient.newBuilder()
            .sslContext(tls)
            .build()
            .send(
                HttpRequest.newBuilder(URI.create(issuer + "/.well-known/" + where)).build(),
                HttpResponse.BodyHandlers.ofString());
    String endpoint = JSONObjectUtils.getString(JSONObjectUtils.parse(answer.body()), "token_endpoint");
    if (!endpoint.startsWith("https://"))
      throw new Refused("insecure", "the metadata names token_endpoint " + endpoint + ", not https");
    return endpoint;
  }

  private ClientRegistration registration(AuthorizationGrantType grant) throws Exception {
    Map<String, Object> client = JSONObjectUtils.getJSONObject(instruction, "client");
    String method = JSONObjectUtils.getString(client, "method");
    return ClientRegistration.withRegistrationId("interop")
        .clientId(JSONObjectUtils.getString(client, "id"))
        .clientSecret(JSONObjectUtils.getString(client, "secret"))
        .clientAuthenticationMethod(
            "client_secret_basic".equals(method)
                ? ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                : ClientAuthenticationMethod.CLIENT_SECRET_POST)
        .authorizationGrantType(grant)
        .scope(String.valueOf(instruction.getOrDefault("scope", "read")).split(" "))
        .tokenUri(tokenEndpoint())
        .build();
  }

  private Map<String, Object> authorized(OAuth2AuthorizedClientProvider provider, ClientRegistration registration) {
    OAuth2AuthorizedClient authorized =
        provider.authorize(
            OAuth2AuthorizationContext.withClientRegistration(registration)
                .principal(new UsernamePasswordAuthenticationToken("interop", null))
                .build());
    OAuth2AccessToken token = authorized.getAccessToken();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("accessToken", token.getTokenValue());
    result.put("tokenType", token.getTokenType().getValue());
    return result;
  }

  /** The assertion an issuer the provider trusts signs: Spring takes a JWT, and makes none. */
  private Jwt assertion() throws Exception {
    Map<String, Object> signer = JSONObjectUtils.getJSONObject(instruction, "assertionIssuer");
    ECKey key = ECKey.parse(JSONObjectUtils.getJSONObject(signer, "privateJwk"));
    Instant now = Instant.now();
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .issuer(JSONObjectUtils.getString(signer, "issuer"))
            .subject(JSONObjectUtils.getString(instruction, "subject"))
            .audience(JSONObjectUtils.getString(instruction, "issuer"))
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(120)))
            .jwtID(UUID.randomUUID().toString())
            .build();
    SignedJWT signed = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
    signed.sign(new ECDSASigner(key));
    return Jwt.withTokenValue(signed.serialize())
        .header("alg", "ES256")
        .claims(c -> c.putAll(claims.getClaims()))
        .issuedAt(now)
        .expiresAt(now.plusSeconds(120))
        .build();
  }

  /** The jwt-bearer grant by Spring's provider, the client authenticated. */
  private Map<String, Object> jwtBearer() throws Exception {
    Jwt jwt = assertion();
    RestClientJwtBearerTokenResponseClient responses = new RestClientJwtBearerTokenResponseClient();
    responses.setRestClient(rest);
    JwtBearerOAuth2AuthorizedClientProvider provider = new JwtBearerOAuth2AuthorizedClientProvider();
    provider.setAccessTokenResponseClient(responses);
    provider.setJwtAssertionResolver(context -> jwt);
    return authorized(provider, registration(AuthorizationGrantType.JWT_BEARER));
  }

  /** Token exchange by Spring's provider: the subject token the driver gives, exchanged for another. */
  private Map<String, Object> tokenExchange() throws Exception {
    Instant now = Instant.now();
    OAuth2AccessToken subject =
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            JSONObjectUtils.getString(instruction, "subjectToken"),
            now,
            now.plusSeconds(60));
    RestClientTokenExchangeTokenResponseClient responses = new RestClientTokenExchangeTokenResponseClient();
    responses.setRestClient(rest);
    TokenExchangeOAuth2AuthorizedClientProvider provider = new TokenExchangeOAuth2AuthorizedClientProvider();
    provider.setAccessTokenResponseClient(responses);
    provider.setSubjectTokenResolver(context -> subject);
    Map<String, Object> result = authorized(provider, registration(AuthorizationGrantType.TOKEN_EXCHANGE));
    result.put("issuedTokenType", "urn:ietf:params:oauth:token-type:access_token");
    return result;
  }

  public static void main(String[] args) throws Exception {
    BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    Map<String, Object> instruction = JSONObjectUtils.parse(in.readLine());
    Map<String, Object> out = new LinkedHashMap<>();
    try {
      Main main = new Main(instruction);
      String flow = JSONObjectUtils.getString(instruction, "flow");
      out.put(
          "result",
          switch (flow) {
            case "jwt-bearer" -> main.jwtBearer();
            case "token-exchange" -> main.tokenExchange();
            default -> throw new Refused("unsupported", "no flow " + flow);
          });
    } catch (Refused refused) {
      out.put("error", Map.of("type", refused.type, "message", String.valueOf(refused.getMessage())));
    } catch (OAuth2AuthorizationException failure) {
      out.put(
          "error",
          Map.of(
              "type", failure.getError().getErrorCode(),
              "message", String.valueOf(failure.getError().getDescription())));
    } catch (Exception failure) {
      out.put(
          "error",
          Map.of("type", failure.getClass().getSimpleName(), "message", String.valueOf(failure.getMessage())));
    }
    System.out.println(JSONObjectUtils.toJSONString(out));
    System.out.flush();
    System.exit(0);
  }
}
