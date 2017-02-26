package emp

// SymmetricMessage represents symmetrically encrypted ET message.
// It partially implements MessageEncrypter interface
type SymmetricMessage struct {
	EncMessage

	rawMessage []byte
}

// Alg returns Message encryption algorithm
func (m SymmetricMessage) Alg() string {
	return m.Algorithm
}

// EncryptedMessage returns ecrypted part of ET message
func (m SymmetricMessage) EncryptedMessage() []byte {
	return m.Message
}

// Signature satisfies MessageEncrypter interface
func (m SymmetricMessage) Signature() []byte {
	return nil
}

// Sign satisfies MessageEncrypter interface
func (m SymmetricMessage) Sign(k []byte) error {
	return nil
}

// Verify satisfies MessageEncrypter interface
func (m SymmetricMessage) Verify(k []byte) error {
	return nil
}
