package emp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// PackBase64 packs JSON representation of message using base64url encoding with padding stripped.
func PackBase64(m MessageEncrypter) ([]byte, error) {
	if len(m.EncryptedMessage()) == 0 {
		return nil, errors.New("Cannot pack unencrypted message")
	}

	jm, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	bs := strings.TrimRight(base64.URLEncoding.EncodeToString(jm), "=")
	return []byte(bs), nil
}
