/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto/x509"
	"github.com/hyperledger/fabric/protoutil"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/stretchr/testify/assert"
)

const (
	testMSPName = "testMSP"
)

func TestNewIdentity(t *testing.T) {
	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)
	mspImpl := &bccspmsp{
		name:         testMSPName,
		bccsp:        cryptoProvider,
		opts:         &x509.VerifyOptions{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()},
		cryptoConfig: &msp.FabricCryptoConfig{IdentityIdentifierHashFunction: bccsp.SHA256},
	}

	// generate self signed cert for test
	now := time.Unix(100000, 0)
	_, cert := generateSelfSignedCert(t, now)
	mspImpl.opts.Roots.AddCert(cert)
	certPubK, err := mspImpl.bccsp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	assert.NoError(t, err)

	identity, err := newIdentity(cert, certPubK, mspImpl)
	assert.NoError(t, err)
	assert.Equal(t, testMSPName, identity.GetIdentifier().Mspid)
	assert.Equal(t, true, len(identity.GetIdentifier().Id) != 0)
	assert.NotNil(t, identity.Validate())
}

func TestExpiresAt(t *testing.T) {
	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)
	mspImpl := &bccspmsp{
		name:         testMSPName,
		bccsp:        cryptoProvider,
		opts:         &x509.VerifyOptions{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()},
		cryptoConfig: &msp.FabricCryptoConfig{IdentityIdentifierHashFunction: bccsp.SHA256},
	}

	// generate self signed cert for test
	now := time.Unix(100000, 0)
	_, cert := generateSelfSignedCert(t, now)
	mspImpl.opts.Roots.AddCert(cert)
	certPubK, err := mspImpl.bccsp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	assert.NoError(t, err)

	identity, err := newIdentity(cert, certPubK, mspImpl)
	assert.NoError(t, err)
	// the self gen cert sets cert.NotAfter at one hour later
	assert.Equal(t, now.Add(1*time.Hour), identity.ExpiresAt().Local())
}

func TestSatisfiesPrincipal(t *testing.T) {
	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)
	mspImpl := &bccspmsp{
		name:         testMSPName,
		bccsp:        cryptoProvider,
		opts:         &x509.VerifyOptions{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()},
		cryptoConfig: &msp.FabricCryptoConfig{IdentityIdentifierHashFunction: bccsp.SHA256},
	}
	mspImpl.internalSatisfiesPrincipalInternalFunc = mspImpl.satisfiesPrincipalInternalV142

	// generate self signed cert for test
	now := time.Unix(100000, 0)
	_, cert := generateSelfSignedCert(t, now)
	mspImpl.opts.Roots.AddCert(cert)
	certPubK, err := mspImpl.bccsp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	assert.NoError(t, err)

	identity, err := newIdentity(cert, certPubK, mspImpl)
	assert.NoError(t, err)
	testMSPPrincipal := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal: protoutil.MarshalOrPanic(&msp.MSPRole{
			MspIdentifier: testMSPName,
			Role:          msp.MSPRole_PEER,
		}),
	}
	err = identity.SatisfiesPrincipal(testMSPPrincipal)
	assert.NoError(t, err)
}
