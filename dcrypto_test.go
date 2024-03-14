package dcrypto_test

import (
	"bytes"
	"dcrypto"
	"testing"
)

func TestEncodeAndDecode(t *testing.T) {
	key, err := dcrypto.NewKey()
	if err != nil {
		t.Fatal(err)
	}

	salt, err := dcrypto.NewSalt()
	if err != nil {
		t.Fatal(err)
	}

	pwd := []byte("some random password")
	data := []byte("some random data")

	encoded, err := dcrypto.Encode(data, key, pwd, salt)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := dcrypto.Decode(encoded, key, pwd, salt)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decoded, data) {
		t.Fatalf("decoded data (%x) is not the same as original data (%x)", decoded, data)
	}
}
