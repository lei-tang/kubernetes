/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oidc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"text/template"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/golang/glog"
	"gopkg.in/square/go-jose.v2"
	"k8s.io/apiserver/pkg/authentication/user"
)

// utilities for loading JOSE keys.

func loadRSAKey(t *testing.T, filepath string, alg jose.SignatureAlgorithm) *jose.JSONWebKey {
	return loadKey(t, filepath, alg, func(b []byte) (interface{}, error) {
		key, err := x509.ParsePKCS1PrivateKey(b)
		if err != nil {
			return nil, err
		}
		return key.Public(), nil
	})
}

func loadRSAPrivKey(t *testing.T, filepath string, alg jose.SignatureAlgorithm) *jose.JSONWebKey {
	return loadKey(t, filepath, alg, func(b []byte) (interface{}, error) {
		return x509.ParsePKCS1PrivateKey(b)
	})
}

func loadECDSAKey(t *testing.T, filepath string, alg jose.SignatureAlgorithm) *jose.JSONWebKey {
	return loadKey(t, filepath, alg, func(b []byte) (interface{}, error) {
		key, err := x509.ParseECPrivateKey(b)
		if err != nil {
			return nil, err
		}
		return key.Public(), nil
	})
}

func loadECDSAPrivKey(t *testing.T, filepath string, alg jose.SignatureAlgorithm) *jose.JSONWebKey {
	return loadKey(t, filepath, alg, func(b []byte) (interface{}, error) {
		return x509.ParseECPrivateKey(b)
	})
}

func loadKey(t *testing.T, filepath string, alg jose.SignatureAlgorithm, unmarshal func([]byte) (interface{}, error)) *jose.JSONWebKey {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		t.Fatalf("load file: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("file contained no PEM encoded data: %s", filepath)
	}
	priv, err := unmarshal(block.Bytes)
	if err != nil {
		t.Fatalf("unmarshal key: %v", err)
	}
	key := &jose.JSONWebKey{Key: priv, Use: "sig", Algorithm: string(alg)}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("computing thumbprint: %v", err)
	}
	key.KeyID = hex.EncodeToString(thumbprint)
	return key
}

// staticKeySet implements oidc.KeySet.
type staticKeySet struct {
	keys []*jose.JSONWebKey
}

func (s *staticKeySet) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) == 0 {
		return nil, fmt.Errorf("jwt contained no signatures")
	}
	kid := jws.Signatures[0].Header.KeyID

	for _, key := range s.keys {
		if key.KeyID == kid {
			return jws.Verify(key)
		}
	}

	return nil, fmt.Errorf("no keys matches jwk keyid")
}

var (
	expired, _ = time.Parse(time.RFC3339Nano, "2009-11-10T22:00:00Z")
	now, _     = time.Parse(time.RFC3339Nano, "2009-11-10T23:00:00Z")
	valid, _   = time.Parse(time.RFC3339Nano, "2009-11-11T00:00:00Z")
)

type claimsTest struct {
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

// Replace formats the contents of v into the provided template.
func replace(tmpl string, v interface{}) string {
	t := template.Must(template.New("test").Parse(tmpl))
	buf := bytes.NewBuffer(nil)
	t.Execute(buf, &v)
	ret := buf.String()
	glog.V(4).Infof("Replaced: %v into: %v", tmpl, ret)
	return ret
}

// newClaimServer returns a new test HTTPS server, which is rigged to return
// OIDC responses to requests that resolve distributed claims. signer is the
// signer used for the served JWT tokens.  claimToResponseMap is a map of
// responses that the server will return for each claim it is given.
func newClaimServer(t *testing.T, keys jose.JSONWebKeySet, signer jose.Signer, claimToResponseMap map[string]string, openIDConfig *string) *httptest.Server {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		glog.V(5).Infof("request: %+v", *r)
		switch r.URL.Path {
		case "/.testing/keys":
			w.Header().Set("Content-Type", "application/json")
			keyBytes, err := json.Marshal(keys)
			if err != nil {
				t.Fatalf("unexpected error while marshaling keys: %v", err)
			}
			glog.V(5).Infof("%v: returning: %+v", r.URL, string(keyBytes))
			w.Write(keyBytes)

		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			glog.V(5).Infof("%v: returning: %+v", r.URL, *openIDConfig)
			w.Write([]byte(*openIDConfig))
		// These claims are tested in the unit tests.
		case "/groups":
			fallthrough
		case "/rabbits":
			if claimToResponseMap == nil {
				t.Errorf("no claims specified in response")
			}
			claim := r.URL.Path[1:] // "/groups" -> "groups"
			glog.V(5).Infof("claim is %v", claim)

			expectedAuth := fmt.Sprintf("Bearer %v_token", claim)
			glog.V(5).Infof("expectedAuth is %v", expectedAuth)

			auth := r.Header.Get("Authorization")
			glog.V(5).Infof("auth is %v", auth)
			if auth != expectedAuth {
				t.Errorf("bearer token expected: %q, was %q", expectedAuth, auth)
			}
			glog.V(5).Infof("claimToResponseMap[claim] is %v", claimToResponseMap[claim])
			jws, err := signer.Sign([]byte(claimToResponseMap[claim]))
			if err != nil {
				t.Errorf("while signing response token: %v", err)
			}
			token, err := jws.CompactSerialize()
			if err != nil {
				t.Errorf("while serializing response token: %v", err)
			}
			w.Write([]byte(token))
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "unexpected URL: %v", r.URL)
		}
	}))
	glog.V(4).Infof("Serving OIDC at: %v", ts.URL)
	return ts
}

// writeTempCert writes out the supplied certificate into a temporary file in
// PEM-encoded format.  Returns the name of the temporary file used.  The caller
// is responsible for cleaning the file up.
func writeTempCert(t *testing.T, cert []byte) string {
	tempFile, err := ioutil.TempFile("", "ca.crt")
	if err != nil {
		t.Fatalf("could not open temp file: %v", err)
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}
	if err := pem.Encode(tempFile, block); err != nil {
		t.Fatalf("could not write to temp file %v: %v", tempFile.Name(), err)
	}
	tempFile.Close()
	return tempFile.Name()
}

func toKeySet(keys []*jose.JSONWebKey) jose.JSONWebKeySet {
	ret := jose.JSONWebKeySet{}
	for _, k := range keys {
		ret.Keys = append(ret.Keys, *k)
	}
	return ret
}

func (c *claimsTest) run(t *testing.T) {
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

func TestToken(t *testing.T) {
	synchronizeTokenIDVerifierForTest = true
	tests := []claimsTest{
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

func TestMain(m *testing.M) {
	flag.Set("alsologtostderr", "true")
	flag.Set("log_dir", "/tmp")
	flag.Set("v", "5")
	flag.Parse()

	ret := m.Run()
	os.Exit(ret)
}
