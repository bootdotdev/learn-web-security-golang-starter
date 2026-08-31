package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
)

const privateKeyBase64 = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfZz8HHXgNEigLYw+NSxsZ15rlOWCsL62wKoMBtOYusmhRANCAAR3iqSaGS3AlikcaUNgzM4y2IXu9/ETjC3lOwASEs3SSW2Fb74iCs/8xqjomTmEPvR1n41oFnU5Uu4g5qwdYTsx"

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func main() {
	if len(os.Args) < 3 {
		os.Exit(1)
	}
	challenge := os.Args[1]
	parsedBaseURL, err := url.Parse(os.Args[2])
	if err != nil || parsedBaseURL.Scheme == "" || parsedBaseURL.Hostname() == "" {
		os.Exit(1)
	}
	origin := parsedBaseURL.Scheme + "://" + parsedBaseURL.Host
	rpID := parsedBaseURL.Hostname()
	if len(os.Args) > 3 && os.Args[3] != "" {
		rpID = os.Args[3]
	}
	mode := ""
	if len(os.Args) > 4 {
		mode = os.Args[4]
	}

	privateKey, err := parsePrivateKey()
	if err != nil {
		os.Exit(1)
	}
	authenticatorData, encodedClientData, signature, err := generateAssertion(privateKey, challenge, origin, rpID, mode)
	if err != nil {
		os.Exit(1)
	}

	fmt.Printf("authenticatorData=%s\n", base64.RawURLEncoding.EncodeToString(authenticatorData))
	fmt.Printf("clientDataJSON=%s\n", base64.RawURLEncoding.EncodeToString(encodedClientData))
	fmt.Printf("signature=%s\n", base64.RawURLEncoding.EncodeToString(signature))
}

func generateAssertion(privateKey *ecdsa.PrivateKey, challenge, origin, rpID, mode string) ([]byte, []byte, []byte, error) {
	authenticatorData := make([]byte, 37)
	rpIDHash := sha256.Sum256([]byte(rpID))
	copy(authenticatorData, rpIDHash[:])
	if mode == "no-uv" {
		authenticatorData[32] = 0x01
	} else {
		authenticatorData[32] = 0x05
	}
	binary.BigEndian.PutUint32(authenticatorData[33:], 0)

	encodedClientData, err := json.Marshal(clientData{
		Type:        "webauthn.get",
		Challenge:   challenge,
		Origin:      origin,
		CrossOrigin: false,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	clientDataHash := sha256.Sum256(encodedClientData)
	signedBytes := append(append([]byte{}, authenticatorData...), clientDataHash[:]...)
	signedDigest := sha256.Sum256(signedBytes)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, signedDigest[:])
	if err != nil {
		return nil, nil, nil, err
	}
	if mode == "bad-sig" {
		signature[len(signature)-1] ^= 0x01
	}
	return authenticatorData, encodedClientData, signature, nil
}

func parsePrivateKey() (*ecdsa.PrivateKey, error) {
	encodedKey, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, err
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(encodedKey)
	if err != nil {
		return nil, err
	}
	return parsedKey.(*ecdsa.PrivateKey), nil
}
