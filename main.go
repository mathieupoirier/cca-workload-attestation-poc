package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/veraison/apiclient/verification"
	"github.com/veraison/ccatoken"
	"github.com/veraison/ear"
)

func main() {
	passportCmd := flag.NewFlagSet("passport", flag.ExitOnError)
	passportName := passportCmd.String("ear", "ear.jwt", "file where the EAR passport is saved")

	_ = flag.NewFlagSet("golden", flag.ExitOnError)

	help := "Available subcommands: 'passport', 'golden'"

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, help)
		os.Exit(0)
	}

	switch os.Args[1] {
	case "passport":
		if err := passportCmd.Parse(os.Args[2:]); err == nil {
			passport(*passportName)
		}
	case "golden":
		golden()
	default:
		fmt.Fprintln(os.Stderr, help)
		os.Exit(0)
	}
}

func passport(out string) {
	cfg := verification.ChallengeResponseConfig{
		NonceSz:         64,
		EvidenceBuilder: TSMEvidenceBuilder{},
		NewSessionURI:   "http://veraison.example:8080/challenge-response/v1/newSession",
		DeleteSession:   true,
	}

	ar, err := cfg.Run()
	if err != nil {
		log.Fatalf("Veraison API client session failed: %v", err)
	}

	jwtString := ar[1 : len(ar)-1]

	if err := processEAR(jwtString); err != nil {
		log.Fatalf("EAR processing failed: %v", err)
	}

	if err = os.WriteFile(out, jwtString, 0644); err != nil {
		log.Fatalf("Saving EAR passport to %q failed: %v", out, err)
	}

	log.Printf("EAR passport saved to %q", out)
}

func processEAR(ares []byte) error {
	earVerificationKey := `{
		"alg": "ES256",
		"crv": "P-256",
		"kty": "EC",
		"x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
		"y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"
	}`

	vfyK, _ := jwk.ParseKey([]byte(earVerificationKey))

	var ar ear.AttestationResult

	if err := ar.Verify(ares, jwa.ES256, vfyK); err != nil {
		return err
	}

	j, _ := ar.MarshalJSONIndent("", " ")
	fmt.Println(string(j))

	return nil
}

type TSMEvidenceBuilder struct{}

func (eb TSMEvidenceBuilder) BuildEvidence(nonce []byte, accept []string) ([]byte, string, error) {
	for _, ct := range accept {
		if ct == "application/eat-collection; profile=http://arm.com/CCA-SSD/1.0.0" {
			evidence, err := getEvidence(nonce)
			if err != nil {
				return nil, "", err
			}

			return evidence, ct, nil
		}
	}

	return nil, "", errors.New("no match on accepted media types")
}

func golden() {
	cbor, err := getEvidence(getRandomNonce())
	if err != nil {
		log.Fatalf("getEvidence failed: %v", err)
	}

	var evidence ccatoken.Evidence

	err = evidence.FromCBOR(cbor)
	if err != nil {
		log.Fatalf("Parsing CCA evidence from CBOR failed: %v", err)
	}

	instID := evidence.GetInstanceID()
	log.Printf("Instance ID: %x\n", *instID)
}

func getEvidence(nonce []byte) ([]byte, error) {
	req := &report.Request{
		InBlob: nonce,
	}

	res, err := linuxtsm.GetReport(req)
	if err != nil {
		return nil, fmt.Errorf("GetReport failed: %s", err)
	}

	return res.OutBlob, nil
}

func getRandomNonce() []byte {
	nonce := make([]byte, 64)
	rand.Read(nonce)
	return nonce
}
