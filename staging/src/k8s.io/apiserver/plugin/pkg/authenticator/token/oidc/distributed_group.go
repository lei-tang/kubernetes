package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"strings"
)

// Extract the distributed group claim from a JWT
func ExtractDistributedGroupClaim(jwt string) ([]string, error) {
	var iss string
	var err error
	glog.V(5).Infof("Enter ExtractDistributedGroupClaim()")
	if iss, err = getJwtIss(jwt); err != nil {
		return nil, err
	}
	glog.V(5).Infof("The issuer of the JWT is: %v", iss)

	//var roots *x509.CertPool
	//if opts.CAFile != "" {
	//	roots, err = cert.NewPool(opts.CAFile)
	//	if err != nil {
	//		return nil, fmt.Errorf("Failed to read the CA file: %v", err)
	//	}
	//} else {
	//	glog.Info("OIDC: No x509 certificates provided, will use host's root CA set")
	//}
	//
	//// Copied from http.DefaultTransport.
	//tr := net.SetTransportDefaults(&http.Transport{
	//	// According to golang's doc, if RootCAs is nil,
	//	// TLS uses the host's root CA set.
	//	TLSClientConfig: &tls.Config{RootCAs: roots},
	//})
	//
	//client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	//
	//ctx := oidc.ClientContext(context.Background(), r.client)
	//provider, err := oidc.NewProvider(ctx, iss)
	//if err != nil {
	//	return nil, err
	//}
	return nil, nil
}

// Get the iss claim from a JWT
func getJwtIss(jwt string) (string, error) {
	// Decoded JWT payload
	var d []byte
	var err error
	s := strings.Split(jwt, ".")
	if len(s) != 3 {
		return "", fmt.Errorf("Invalid JWT with %v components", len(s))
	}
	if len(s[1]) == 0 {
		return "", fmt.Errorf("The payload of the JWT is empty")
	}
	if d, err = base64.RawURLEncoding.DecodeString(s[1]); err != nil {
		return "", fmt.Errorf("Fail to decode the JWT payload: %v", err)
	}
	issuer := struct {
		Iss string `json:"iss"`
	}{}
	// Extract iss claim from the payload
	if err = json.Unmarshal(d, &issuer); err != nil {
		return "", fmt.Errorf("Fail to parse json: %v", err)
	}
	return issuer.Iss, nil
}

