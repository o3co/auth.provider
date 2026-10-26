// The Go adapter: one flow per run, told on its first input line, done with golang.org/x/oauth2 and
// go-oidc's own calls; each browser step is asked of the driver, and the result is what they gave back.
// It trusts the front's certificate its instruction gives, and nothing else.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/jwt"
)

type client struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Secret string `json:"secret"`
}

type instruction struct {
	Flow                  string `json:"flow"`
	Issuer                string `json:"issuer"`
	CA                    string `json:"ca"`
	Client                client `json:"client"`
	RedirectURI           string `json:"redirectUri"`
	Scope                 string `json:"scope"`
	Resource              string `json:"resource"`
	PostLogoutRedirectURI string `json:"postLogoutRedirectUri"`
	// The issuer whose assertion is presented by the jwt-bearer grant, with its private key.
	AssertionIssuer *struct {
		Issuer     string `json:"issuer"`
		PrivatePem string `json:"privatePem"`
	} `json:"assertionIssuer"`
	Subject     string `json:"subject"`
	Backchannel *struct {
		Port int    `json:"port"`
		Path string `json:"path"`
	} `json:"backchannel"`
}

// refused is a failure the adapter reports as the library or the provider named it.
type refused struct{ kind, message string }

func (r refused) Error() string { return r.message }

var lines = bufio.NewScanner(os.Stdin)

func write(v any) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

func ask(question map[string]any) (map[string]any, error) {
	write(question)
	if !lines.Scan() {
		return nil, errors.New("no answer from the driver")
	}
	var answer map[string]any
	err := json.Unmarshal(lines.Bytes(), &answer)
	return answer, err
}

func random() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// trusting is an HTTP client whose TLS trusts the front's certificate alone, and that follows a
// redirect only to https, as many as Go's default (10): one to plain http would send the request's
// body and Authorization again in clear, past the endpoints discovered() checks.
func trusting(pem string) *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(pem))
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refused a redirect to %s, not https", req.URL.Redacted())
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}
}

type run struct {
	in       instruction
	ctx      context.Context
	provider *oidc.Provider
	metadata map[string]any
}

// discovered resolves the provider, refusing a discovery that names an endpoint or key set over anything but https.
func (r *run) discovered() error {
	p, err := oidc.NewProvider(r.ctx, r.in.Issuer)
	if err != nil {
		return err
	}
	if err := p.Claims(&r.metadata); err != nil {
		return err
	}
	for key, value := range r.metadata {
		s, ok := value.(string)
		if (strings.HasSuffix(key, "_endpoint") || key == "jwks_uri") && ok && !strings.HasPrefix(s, "https://") {
			return refused{"insecure", fmt.Sprintf("the discovery names %s %s, not https", key, s)}
		}
	}
	r.provider = p
	return nil
}

func (r *run) config() *oauth2.Config {
	endpoint := r.provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	if r.in.Client.Method == "client_secret_basic" {
		endpoint.AuthStyle = oauth2.AuthStyleInHeader
	}
	scope := r.in.Scope
	if scope == "" {
		scope = "openid"
	}
	return &oauth2.Config{
		ClientID:     r.in.Client.ID,
		ClientSecret: r.in.Client.Secret,
		Endpoint:     endpoint,
		RedirectURL:  r.in.RedirectURI,
		Scopes:       strings.Fields(scope),
	}
}

type signedIn struct {
	token  *oauth2.Token
	id     *oidc.IDToken
	claims map[string]any
}

// signIn runs the code flow with PKCE, state and nonce; go-oidc checks no nonce, so the adapter does, as an app must.
func (r *run) signIn(conf *oauth2.Config) (*signedIn, error) {
	verifier, state, nonce := oauth2.GenerateVerifier(), random(), random()
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce)}
	if r.in.Resource != "" {
		options = append(options, oauth2.SetAuthURLParam("resource", r.in.Resource))
	}
	answer, err := ask(map[string]any{"ask": "browse", "url": conf.AuthCodeURL(state, options...)})
	if err != nil {
		return nil, err
	}
	location, err := url.Parse(fmt.Sprint(answer["location"]))
	if err != nil {
		return nil, err
	}
	query := location.Query()
	if query.Get("state") != state {
		return nil, refused{"state", "the answer's state is not the request's"}
	}
	// RFC 9207: an answer naming a provider names the one the request went to.
	if iss := query.Get("iss"); iss != "" && iss != r.in.Issuer {
		return nil, refused{"iss", "the answer's iss is " + iss}
	}
	exchange := []oauth2.AuthCodeOption{oauth2.VerifierOption(verifier)}
	if r.in.Resource != "" {
		exchange = append(exchange, oauth2.SetAuthURLParam("resource", r.in.Resource))
	}
	token, err := conf.Exchange(r.ctx, query.Get("code"), exchange...)
	if err != nil {
		return nil, err
	}
	raw, _ := token.Extra("id_token").(string)
	id, err := r.provider.Verifier(&oidc.Config{ClientID: conf.ClientID}).Verify(r.ctx, raw)
	if err != nil {
		return nil, err
	}
	if id.Nonce != nonce {
		return nil, refused{"nonce", "the ID token's nonce is not the request's"}
	}
	var claims map[string]any
	if err := id.Claims(&claims); err != nil {
		return nil, err
	}
	return &signedIn{token, id, claims}, nil
}

func (r *run) login() (any, error) {
	conf := r.config()
	in, err := r.signIn(conf)
	if err != nil {
		return nil, err
	}
	info, err := r.provider.UserInfo(r.ctx, oauth2.StaticTokenSource(in.token))
	if err != nil {
		return nil, err
	}
	var userinfo map[string]any
	if err := info.Claims(&userinfo); err != nil {
		return nil, err
	}
	// Userinfo is the signed-in user's only where it names the ID token's subject (OpenID Connect Core §5.3.2).
	if info.Subject == "" || info.Subject != in.id.Subject {
		return nil, refused{"userinfo_subject", "the userinfo names another subject, or none"}
	}
	scope, _ := in.token.Extra("scope").(string)
	return map[string]any{
		"idToken":      in.claims,
		"userinfo":     userinfo,
		"tokenType":    in.token.TokenType,
		"scope":        scope,
		"refreshToken": in.token.RefreshToken != "",
	}, nil
}

// refresh signs in, refreshes by a token source whose token has expired, then presents the replaced refresh token again.
func (r *run) refresh() (any, error) {
	conf := r.config()
	in, err := r.signIn(conf)
	if err != nil {
		return nil, err
	}
	first := in.token.RefreshToken
	if first == "" {
		return nil, refused{"no_refresh_token", "the code's token answer held no refresh token"}
	}
	expired := func() *oauth2.Token { return &oauth2.Token{RefreshToken: first, Expiry: time.Now().Add(-time.Hour)} }
	renewed, err := conf.TokenSource(r.ctx, expired()).Token()
	if err != nil {
		return nil, err
	}
	replayed := "taken"
	if _, err := conf.TokenSource(r.ctx, expired()).Token(); err != nil {
		replayed = "refused"
		var retrieve *oauth2.RetrieveError
		if errors.As(err, &retrieve) && retrieve.ErrorCode != "" {
			replayed = retrieve.ErrorCode
		}
	}
	return map[string]any{
		"accessToken": renewed.AccessToken != "",
		"rotated":     renewed.RefreshToken != "" && renewed.RefreshToken != first,
		"replayed":    replayed,
	}, nil
}

func (r *run) resource() (any, error) {
	in, err := r.signIn(r.config())
	if err != nil {
		return nil, err
	}
	return map[string]any{"accessToken": in.token.AccessToken}, nil
}

// clientCredentials is the client credentials grant, the client authenticated by its secret.
func (r *run) clientCredentials() (any, error) {
	conf := r.config()
	cc := clientcredentials.Config{
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		TokenURL:     conf.Endpoint.TokenURL,
		Scopes:       conf.Scopes,
		AuthStyle:    conf.Endpoint.AuthStyle,
	}
	token, err := cc.Token(r.ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"accessToken": token.AccessToken, "tokenType": token.TokenType}, nil
}

// device runs the device authorization grant: the driver, as the user, approves the code, then the library polls.
func (r *run) device() (any, error) {
	conf := r.config()
	started, err := conf.DeviceAuth(r.ctx)
	if err != nil {
		return nil, err
	}
	if _, err := ask(map[string]any{"ask": "device", "userCode": started.UserCode, "verificationUri": started.VerificationURI}); err != nil {
		return nil, err
	}
	token, err := conf.DeviceAccessToken(r.ctx, started)
	if err != nil {
		return nil, err
	}
	return map[string]any{"accessToken": token.AccessToken, "tokenType": token.TokenType}, nil
}

// backchannelLogout signs in, ends the session at the end-session endpoint, and takes the logout token the
// provider posts to the receiver the client registered, verified by go-oidc's VerifyLogout.
func (r *run) backchannelLogout() (any, error) {
	if r.in.Backchannel == nil {
		return nil, refused{"instruction", "no receiver named"}
	}
	told := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(r.in.Backchannel.Path, func(w http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err == nil {
			select {
			case told <- req.PostForm.Get("logout_token"):
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(r.in.Backchannel.Port))
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	conf := r.config()
	in, err := r.signIn(conf)
	if err != nil {
		return nil, err
	}
	// go-oidc builds no end-session URL; it is formed from the discovery as RP-Initiated Logout says.
	endpoint, _ := r.metadata["end_session_endpoint"].(string)
	state := random()
	ending, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	raw, _ := in.token.Extra("id_token").(string)
	ending.RawQuery = url.Values{"id_token_hint": {raw}, "post_logout_redirect_uri": {r.in.PostLogoutRedirectURI}, "state": {state}}.Encode()
	answer, err := ask(map[string]any{"ask": "logout", "url": ending.String()})
	if err != nil {
		return nil, err
	}
	var token string
	select {
	case token = <-told:
	case <-time.After(20 * time.Second):
		return nil, refused{"timeout", "no logout token was posted"}
	}
	logout, err := r.provider.Verifier(&oidc.Config{ClientID: conf.ClientID}).VerifyLogout(r.ctx, token)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"sub":         logout.Subject,
		"sid":         logout.SessionID,
		"signedInSub": in.id.Subject,
		"signedInSid": in.claims["sid"],
		"location":    answer["location"],
	}, nil
}

// jwtBearerNoClient gets a token by the jwt-bearer grant as x/oauth2/jwt sends it: an RS256 assertion
// of the issuer's, its `aud` the token endpoint, and no client authentication (RFC 7523 §3.1).
func (r *run) jwtBearerNoClient() (any, error) {
	issuer := r.in.AssertionIssuer
	if issuer == nil {
		return nil, refused{"instruction", "no assertion issuer"}
	}
	conf := &jwt.Config{
		Email:         issuer.Issuer,
		PrivateKey:    []byte(issuer.PrivatePem),
		Subject:       r.in.Subject,
		Scopes:        strings.Fields(r.in.Scope),
		TokenURL:      r.provider.Endpoint().TokenURL,
		Expires:       5 * time.Minute,
		PrivateClaims: map[string]any{"jti": random()},
	}
	token, err := conf.TokenSource(r.ctx).Token()
	if err != nil {
		return nil, err
	}
	return map[string]any{"accessToken": token.AccessToken, "tokenType": token.TokenType}, nil
}

func main() {
	lines.Buffer(make([]byte, 1<<20), 1<<24)
	if !lines.Scan() {
		os.Exit(2)
	}
	var in instruction
	if err := json.Unmarshal(lines.Bytes(), &in); err != nil {
		write(map[string]any{"error": map[string]any{"type": "instruction", "message": err.Error()}})
		return
	}
	httpClient := trusting(in.CA)
	ctx := oidc.ClientContext(context.WithValue(context.Background(), oauth2.HTTPClient, httpClient), httpClient)
	r := &run{in: in, ctx: ctx}
	flows := map[string]func() (any, error){
		"login":                     r.login,
		"public-login":              r.login,
		"cimd":                      r.login,
		"refresh":                   r.refresh,
		"resource":                  r.resource,
		"client-credentials-secret": r.clientCredentials,
		"public-device":             r.device,
		"backchannel-logout":        r.backchannelLogout,
		"jwt-bearer-no-client":      r.jwtBearerNoClient,
	}
	flow, known := flows[in.Flow]
	var result any
	err := r.discovered()
	if err == nil && !known {
		err = refused{"unsupported", "no flow " + in.Flow}
	}
	if err == nil {
		result, err = flow()
	}
	if err != nil {
		kind := fmt.Sprintf("%T", err)
		var said refused
		var retrieve *oauth2.RetrieveError
		if errors.As(err, &said) {
			kind = said.kind
		} else if errors.As(err, &retrieve) && retrieve.ErrorCode != "" {
			kind = retrieve.ErrorCode
		}
		write(map[string]any{"error": map[string]any{"type": kind, "message": err.Error()}})
		return
	}
	write(map[string]any{"result": result})
}
