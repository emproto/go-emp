package emp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// AsymmetricMessage represents asymmetrically encrypted ET message.
// It implements MessageEncrypter interface
type AsymmetricMessage struct {
	EncMessage

	rawMessage []byte
	hash       crypto.Hash
}

// Alg returns Message encryption algorithm
func (m AsymmetricMessage) Alg() string {
	return m.Algorithm
}

// EncryptedMessage returns ecrypted part of ET message
func (m AsymmetricMessage) EncryptedMessage() []byte {
	return m.Message
}

// Signature returns signature part of ET message
func (m AsymmetricMessage) Signature() []byte {
	return m.Sig
}

// Decrypt decrypts received message using given private key bytes
func (m *AsymmetricMessage) Decrypt(privateKey []byte) ([]byte, error) {
	pk, err := loadPrivateKeyBytes(privateKey)
	if err != nil {
		return nil, err
	}

	rawMsgBytes, err := rsa.DecryptOAEP(m.hash.New(), rand.Reader, pk, m.Message, nil)
	if err != nil {
		return nil, err
	}

	m.rawMessage = rawMsgBytes
	return rawMsgBytes, nil
}

// Encrypt encrypts message to be sent using given private key
func (m *AsymmetricMessage) Encrypt(pubkey []byte) error {
	ki, err := loadPublicKeyBytes(pubkey)
	if err != nil {
		return err
	}

	pk, ok := ki.(*rsa.PublicKey)
	if !ok {
		return errors.New("Non RSA public key given")
	}

	encryptedMessage, err := rsa.EncryptOAEP(m.hash.New(), rand.Reader, pk, m.rawMessage, nil)
	if err != nil {
		return err
	}

	m.Message = encryptedMessage
	return nil
}

// Sign signs message using given private key
func (m *AsymmetricMessage) Sign(privateKey []byte) error {
	if len(m.EncryptedMessage()) == 0 {
		return errors.New("Cannot sign unencrypted message")
	}

	pk, err := loadPrivateKeyBytes(privateKey)
	if err != nil {
		return err
	}

	opts := rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}

	h := m.hash.New()
	h.Write(m.EncryptedMessage())
	hashed := h.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, pk, m.hash, hashed, &opts)
	if err != nil {
		return err
	}

	m.Sig = signature
	return nil
}

// Verify checks message signature
func (m RSAMessage) Verify(pubkey []byte) error {
	ki, err := loadPublicKeyBytes(pubkey)
	if err != nil {
		return err
	}

	pk, ok := ki.(*rsa.PublicKey)
	if !ok {
		return errors.New("Non RSA public key given")
	}

	opts := rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}

	h := m.hash.New()
	h.Write(m.EncryptedMessage())
	hashed := h.Sum(nil)

	return rsa.VerifyPSS(pk, m.hash, hashed[:], m.Signature(), &opts)
}

func loadPrivateKeyBytes(privateKeyBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return nil, errors.New("Failed to parse PEM block containing the private keys")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Can't parse private key: %s", err.Error())
	}

	return privKey, nil
}

func loadPublicKeyBytes(publicKeyBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		return nil, errors.New("Failed to parse PEM block containing the public key")
	}

	return x509.ParsePKIXPublicKey(block.Bytes)
}
