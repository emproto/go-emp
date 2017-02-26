package emp

import "crypto"

// RSAMessage represents RSA encrypted ET message.
// It is composition type of base AsymmetricMessage struct
type RSAMessage struct {
	AsymmetricMessage
}

// NewRsaSha256Message returns new unencrypted message
func NewRsaSha256Message(text string) *RSAMessage {
	return &RSAMessage{
		AsymmetricMessage{
			EncMessage: EncMessage{
				Algorithm: AlgRsaSha256,
			},
			rawMessage: []byte(text),
			hash:       crypto.SHA256,
		},
	}
}

// NewRsaSha512Message returns new unencrypted message
func NewRsaSha512Message(text string) *RSAMessage {
	return &RSAMessage{
		AsymmetricMessage{
			EncMessage: EncMessage{
				Algorithm: AlgRsaSha512,
			},
			rawMessage: []byte(text),
			hash:       crypto.SHA512,
		},
	}
}

// LoadRsaMessage populates RSAMessage struct with given emsg data
func LoadRsaMessage(emsg MessageEncrypter) *RSAMessage {
	hash := crypto.SHA256
	if emsg.Alg() == AlgRsaSha512 {
		hash = crypto.SHA512
	}

	return &RSAMessage{
		AsymmetricMessage{
			EncMessage: EncMessage{
				Algorithm: emsg.Alg(),
				Message:   emsg.EncryptedMessage(),
				Sig:       emsg.Signature(),
			},
			hash: hash,
		},
	}
}
