package emp

import "errors"

// MessageEncrypter represents ET message
type MessageEncrypter interface {
	Alg() string
	EncryptedMessage() []byte
	Signature() []byte

	Decrypt([]byte) ([]byte, error)
	Encrypt([]byte) error
	Sign([]byte) error
	Verify([]byte) error
}

// EncMessage is a base struct like json.RawMessage.
// It already implements MessageEncrypter interface, but you must not use this directly.
// Use it for struct composition instead.
type EncMessage struct {
	Algorithm string `json:"alg"`
	Message   []byte `json:"msg"`
	Sig       []byte `json:"sig,omitempty"`
}

// Alg satisfies MessageEncrypter interface
func (m EncMessage) Alg() string {
	return m.Algorithm
}

// EncryptedMessage satisfies MessageEncrypter interface
func (m EncMessage) EncryptedMessage() []byte {
	return m.Message
}

// Signature satisfies MessageEncrypter interface
func (m EncMessage) Signature() []byte {
	return m.Sig
}

// Decrypt satisfies MessageEncrypter interface
func (m EncMessage) Decrypt(k []byte) ([]byte, error) {
	return nil, errors.New("Decrypt method must be overridden")
}

// Encrypt satisfies MessageEncrypter interface
func (m EncMessage) Encrypt(k []byte) error {
	return errors.New("Encrypt method must be overridden")
}

// Sign satisfies MessageEncrypter interface
func (m EncMessage) Sign(k []byte) error {
	return errors.New("Sign method must be overridden")
}

// Verify satisfies MessageEncrypter interface
func (m EncMessage) Verify(k []byte) error {
	return errors.New("Verify method must be overridden")
}
