package oidc

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/golang/glog"
	"gopkg.in/square/go-jose.v2"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"
	"k8s.io/apiserver/pkg/authentication/user"
)

type groupClaimTest struct {
	name               string
	options            Options
	now                time.Time
	signingKey         *jose.JSONWebKey
	pubKeys            []*jose.JSONWebKey
	claims             string
	want               *user.DefaultInfo
	wantSkip           bool
	wantErr            bool
	wantInitErr        bool
	claimToResponseMap map[string]string
	openIDConfig       string
}

func (c *groupClaimTest) run(t *testing.T) {
	var (
		signer jose.Signer
		err    error
	)
	if c.signingKey != nil {
		// Initialize the signer only in the tests that make use of it.  We can
		// not defer this initialization because the test server uses it too.
		signer, err = jose.NewSigner(jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(c.signingKey.Algorithm),
			Key:       c.signingKey,
		}, nil)
		if err != nil {
			t.Fatalf("initialize signer: %v", err)
		}
	}
	// The HTTPS server used for requesting distributed groups claims.
	ts := newClaimServer(t, toKeySet(c.pubKeys), signer, c.claimToResponseMap, &c.openIDConfig)
	defer ts.Close()

	// Make the certificate of the helper server available to the authenticator
	// by writing its root CA certificate into a temporary file.
	tempFileName := writeTempCert(t, ts.TLS.Certificates[0].Certificate[0])
	defer os.Remove(tempFileName)
	c.options.CAFile = tempFileName

	// Allow claims to refer to the serving URL of the test server.  For this,
	// substitute all references to {{.URL}} in appropriate places.
	glog.V(5).Infof("ts.URL is %v", ts.URL)
	v := struct{ URL string }{URL: ts.URL}
	c.claims = replace(c.claims, &v)
	c.openIDConfig = replace(c.openIDConfig, &v)
	c.options.IssuerURL = replace(c.options.IssuerURL, &v)
	for claim, response := range c.claimToResponseMap {
		c.claimToResponseMap[claim] = replace(response, &v)
	}

	// Initialize the authenticator.
	a, err := newAuthenticator(c.options, func(ctx context.Context, a *Authenticator, config *oidc.Config) {
		// Set the verifier to use the public key set instead of reading from a remote.
		a.setVerifier(oidc.NewVerifier(
			c.options.IssuerURL,
			&staticKeySet{keys: c.pubKeys},
			config,
		))
	})
	if err != nil {
		if !c.wantInitErr {
			t.Fatalf("initialize authenticator: %v", err)
		}
		return
	}
	if c.wantInitErr {
		t.Fatalf("wanted initialization error")
	}

	// Sign and serialize the claims in a JWT.
	jws, err := signer.Sign([]byte(c.claims))
	if err != nil {
		t.Fatalf("sign claims: %v", err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize token: %v", err)
	}

	got, ok, err := a.AuthenticateToken(token)
	if err != nil {
		if !c.wantErr {
			t.Fatalf("authenticate token: %v", err)
		}
		return
	}

	if c.wantErr {
		t.Fatalf("expected error authenticating token")
	}
	if !ok {
		if !c.wantSkip {
			// We don't have any cases where we return (nil, false, nil)
			t.Fatalf("no error but token not authenticated")
		}
		return
	}
	if c.wantSkip {
		t.Fatalf("expected authenticator to skip token")
	}

	gotUser := got.(*user.DefaultInfo)
	if !reflect.DeepEqual(gotUser, c.want) {
		t.Fatalf("wanted user=%#v, got=%#v", c.want, gotUser)
	}
}


func loadJSONWebPrivateKey(t *testing.T, path string, alg jose.SignatureAlgorithm) *jose.JSONWebKey {
	d, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
		return nil
	}
	p, _ := pem.Decode(d)
	if p == nil {
		t.Fatalf("Failed to decode the PEM file.")
		return nil
	}
	priv, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse private key.")
		return nil
	}
	key := &jose.JSONWebKey{Key: priv, Algorithm: string(alg)}
	hash, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to compute a SHA256 hash for the key: %v", err)
		return nil
	}
	key.KeyID = hex.EncodeToString(hash)
	return key
}

func TestExtractDistributedGroupClaim(t *testing.T) {
	jwt := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ5NmNmNThmY2Q5YzZhMmRiYTY1ZjcxZGY4YjhhNjVjZDll" +
			"M2JlODEyNzY5NTE4NGZlNjI2OWI4OWZjYzQzZDAifQ.ewoJCQkJImlzcyI6ICJodHRwczovLzEyNy4wLj" +
			"AuMTo0Mzg3MyIsCgkJCQkiYXVkIjogIm15LWNsaWVudCIsCgkJCQkidXNlcm5hbWUiOiAiamFuZSIsCgk" +
			"JCQkiX2NsYWltX25hbWVzIjogewoJCQkJCQkiZ3JvdXBzIjogInNyYzEiCgkJCQl9LAoJCQkJIl9jbGFp" +
			"bV9zb3VyY2VzIjogewoJCQkJCQkic3JjMSI6IHsKCQkJCQkJCQkiZW5kcG9pbnQiOiAiaHR0cHM6Ly8xM" +
			"jcuMC4wLjE6NDM4NzMvZ3JvdXBzIiwKCQkJCQkJCQkiYWNjZXNzX3Rva2VuIjogImdyb3Vwc190b2tlbi" +
			"IKCQkJCQkJfQoJCQkJfSwKCQkJCSJleHAiOiAxMjU3ODk3NjAwCgkJCX0.lodMvena4YsvHElVuwdKnzp" +
			"McCv_oStQlmfcgikpN1iB1jlZXMygqyWbm_DJ3A9bGQ2tHiaZB5ME1aijlu59CrURqeERl57KD7YQ6Dv-" +
			"VczyotPyfdT6xLExtbHX2ZG0qIZOG4rJD5wdBpsR6XKB1X2_K_MjhDq4TVrIMi53RhtHaHPtBW79JAjUb" +
			"J9TjhAqWQeks5qcmxpiqBvlAJqZEiJllr1OKemIBsTPlSd98DkDdD0hIJFVE90p8k5c8VBYNHe4NlDsdo" +
			"rKt3q71OuyoTr4-KTcaBKf4lX4Q8ViDfyoYijG-bwxH0DitwboXIAy4-KfC6GHOPPo7gHVDFNs6w"

	groups, err := ExtractDistributedGroupClaim(jwt)
	if err != nil {
		t.Fatalf("Failed to extract group claim: %v", err)
	}
	glog.V(5).Infof("groups: %+v", groups)

	privKey := loadJSONWebPrivateKey(t, "testdata/rsa_1.pem", jose.RS256)
	if privKey == nil {
		t.Fatalf("Failed to load private key from file")
	}
	glog.V(5).Infof("public key is: %+v", privKey.Public())
}

func TestAuthnToken(t *testing.T) {
	synchronizeTokenIDVerifierForTest = true
	tests := []groupClaimTest{
		{
			name: "groups-distributed",
			options: Options{
				IssuerURL:     "{{.URL}}",
				ClientID:      "my-client",
				UsernameClaim: "username",
				GroupsClaim:   "groups",
				now:           func() time.Time { return now },
			},
			signingKey: loadRSAPrivKey(t, "testdata/rsa_1.pem", jose.RS256),
			pubKeys: []*jose.JSONWebKey{
				loadRSAKey(t, "testdata/rsa_1.pem", jose.RS256),
			},
			claims: fmt.Sprintf(`{
				"iss": "{{.URL}}",
				"aud": "my-client",
				"username": "jane",
				"_claim_names": {
						"groups": "src1"
				},
				"_claim_sources": {
						"src1": {
								"endpoint": "{{.URL}}/groups",
								"access_token": "groups_token"
						}
				},
				"exp": %d
			}`, valid.Unix()),
			claimToResponseMap: map[string]string{
				"groups": fmt.Sprintf(`{
					"iss": "{{.URL}}",
				    "aud": "my-client",
					"groups": ["team1", "team2"],
					"exp": %d
			     }`, valid.Unix()),
			},
			openIDConfig: `{
					"issuer": "{{.URL}}",
					"jwks_uri": "{{.URL}}/.testing/keys"
			}`,
			want: &user.DefaultInfo{
				Name:   "jane",
				Groups: []string{"team1", "team2"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}
