# CCA workload attestation PoC

A proof-of-concept, self-contained executable that demonstrates how CCA attestation can be used.

## Building and Installing

Statically cross-compile for `aarch64/linux` with:

```sh
CGO_ENABLED=0 GOARCH=arm64 GOOS=linux go build -ldflags="-s -w"
```

For now, to deploy the executable to a confidential guest, you will need to mount a shared folder in the guest and manually copy the executable over.

Eventually, this project will be added to the buildroot environment of the guest OS.

## Usage

### Setup

* Add a `veraison.example` entry in the guest's `/etc/hosts` with the IP address of the Veraison service.

### Getting an Attestation Passport

In the confidential guest, execute:

```sh
/root/cca-workload-attestation-poc passport
```

This proof-of-concept will:

1. Open a challenge-response session with a Veraison verifier
1. Ask for an attestation report for the received challenge using the `TSM_REPORT` ABI
1. Send the obtained CCA attestation token for verification
1. Receive the EAT Attestation Result (EAR) token
1. Print the EAR contents to stdout

### (TODO) Getting an X.509 Certificate using Attested CSR

### (TODO) Establishing an Attested TLS Session