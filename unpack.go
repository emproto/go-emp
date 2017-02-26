package emp

import (
	"encoding/base64"
	"encoding/json"
)

// UnpackBase64 unpacks base64url encoded JSON representation of message.
func UnpackBase64(m []byte) (MessageEncrypter, error) {
	jm, err := base64.URLEncoding.DecodeString(string(m))
	if err != nil {
		return nil, err
	}

	var emsg EncMessage
	err = json.Unmarshal(jm, &emsg)
	if err != nil {
		return nil, err
	}

	return emsg, nil
}
