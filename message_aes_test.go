package emp

import "testing"

var (
	secret128 = []byte("TestAES128Secret")
	secret256 = []byte("TestAES128SecretTestAES128Secret")
)

/* AES128 */

func TestEncryptAes128(t *testing.T) {
	msg := NewAes128Message("Hello, EMP!")

	err := msg.Encrypt(secret128)
	if err != nil {
		t.Fatalf("Cannot encrypt message: %s", err)
	}

	_, err = PackBase64(msg)
	if err != nil {
		t.Fatalf("Cannot pack message: %s", err)
	}
}

func TestDecryptAes128(t *testing.T) {
	msg := NewAes128Message("Hello, EMP!")

	err := msg.Encrypt(secret128)
	if err != nil {
		t.Fatalf("Cannot encrypt message: %s", err)
	}

	pb, err := PackBase64(msg)
	if err != nil {
		t.Fatalf("Cannot pack message: %s", err)
	}

	emsg, err := UnpackBase64(pb)
	if err != nil {
		t.Fatalf("Cannot unpack base64 message: %s", err)
	}

	if emsg.Alg() != AlgAes128 {
		t.Fatalf("Expected algorithm \"%s\" got %s", AlgAes128, emsg.Alg())
	}

	aesMsg := LoadAesMessage(emsg)

	_, err = aesMsg.Decrypt(secret128)
	if err != nil {
		t.Fatalf("Cannot decrypt AES128 message: %s", err)
	}
}

/* AES256 */

func TestEncryptAes256(t *testing.T) {
	msg := NewAes256Message("Hello, EMP!")

	err := msg.Encrypt(secret256)
	if err != nil {
		t.Fatalf("Cannot encrypt message: %s", err)
	}

	_, err = PackBase64(msg)
	if err != nil {
		t.Fatalf("Cannot pack message: %s", err)
	}
}

func TestDecryptAes256(t *testing.T) {
	msg := NewAes256Message("Hello, EMP!")

	err := msg.Encrypt(secret256)
	if err != nil {
		t.Fatalf("Cannot encrypt message: %s", err)
	}

	pb, err := PackBase64(msg)
	if err != nil {
		t.Fatalf("Cannot pack message: %s", err)
	}

	emsg, err := UnpackBase64(pb)
	if err != nil {
		t.Fatalf("Cannot unpack base64 message: %s", err)
	}

	if emsg.Alg() != AlgAes256 {
		t.Fatalf("Expected algorithm \"%s\" got %s", AlgAes256, emsg.Alg())
	}

	aesMsg := LoadAesMessage(emsg)

	_, err = aesMsg.Decrypt(secret256)
	if err != nil {
		t.Fatalf("Cannot decrypt AES128 message: %s", err)
	}
}
