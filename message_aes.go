package emp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// ErrAESSecretLength is a default error for invalid secret length
var ErrAesSecretLength = errors.New("AES secret must be 16 bytes long for AES128 or 32 bytes long for AES256")

// AesMessage represents AES encrypted ET message.
// It is composition type of base SymmetricMessage struct
type AesMessage struct {
	SymmetricMessage
}

// Decrypt decrypts received message using given secret bytes
func (m AesMessage) Decrypt(secret []byte) ([]byte, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	if (len(m.Message) % aes.BlockSize) != 0 {
		return nil, errors.New("Invalid message length")
	}

	msg := m.Message[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, m.Message[:aes.BlockSize])
	cfb.XORKeyStream(msg, msg)

	return msg, nil
}

// Encrypt encrypts message to be sent using given secret
func (m *AesMessage) Encrypt(secret []byte) error {
	switch m.Algorithm {
	case AlgAes128:
		if len(secret) != 16 {
			return ErrAesSecretLength
		}
	case AlgAes256:
		if len(secret) != 32 {
			return ErrAesSecretLength
		}
	default:
		return errors.New("Unknown AES algorithm type")
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return err
	}

	padding := aes.BlockSize - len(m.rawMessage)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	msg := append(m.rawMessage, padtext...)
	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(msg))

	m.Message = ciphertext
	return nil
}

// NewAes128Message returns new or received ET message
func NewAes128Message(text string) *AesMessage {
	return &AesMessage{
		SymmetricMessage{
			EncMessage: EncMessage{
				Algorithm: AlgAes128,
			},
			rawMessage: []byte(text),
		},
	}
}

// NewAes256Message returns new or received ET message
func NewAes256Message(text string) *AesMessage {
	return &AesMessage{
		SymmetricMessage{
			EncMessage: EncMessage{
				Algorithm: AlgAes256,
			},
			rawMessage: []byte(text),
		},
	}
}

// LoadAesMessage populates RSAMessage struct with given emsg data
func LoadAesMessage(emsg MessageEncrypter) *AesMessage {
	return &AesMessage{
		SymmetricMessage{
			EncMessage: EncMessage{
				Algorithm: emsg.Alg(),
				Message:   emsg.EncryptedMessage(),
			},
		},
	}
}
