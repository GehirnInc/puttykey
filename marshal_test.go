package puttykey

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"testing"
)

type MarshalTestCase struct {
	name     string
	expected string
}

var MarshalTestCases = []MarshalTestCase{
	MarshalTestCase{
		name:     "testdata/id_rsa_1",
		expected: "testdata/id_rsa_1.ppk",
	},
}

func TestMarshal(t *testing.T) {
	for _, testCase := range MarshalTestCases {
		key, err := loadPrivateKey(testCase.name)
		if err != nil {
			t.Log(err)
			t.Fail()
			continue
		}

		got, err := Marshal(key, "Gehirn RS2@2014-03-23 16:48:08", "")
		if err != nil {
			t.Log(err)
			t.Fail()
			continue
		}

		expected, err := ioutil.ReadFile(testCase.expected)
		if err != nil {
			t.Log(err)
			t.Fail()
			continue
		}

		if !bytes.Equal(got, expected) {
			t.Log(string(got))
			t.Log(string(expected))
			t.Fail()
		}
	}
}

func loadPrivateKey(name string) (priv *rsa.PrivateKey, err error) {
	body, err := ioutil.ReadFile(name)
	if err != nil {
		return
	}

	block, rest := pem.Decode(body)
	if len(rest) > 0 {
		err = errors.New("Invalid test data")
		return
	} else if block.Type != "RSA PRIVATE KEY" {
		err = errors.New("Invalid test data")
		return
	}

	priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return
	}

	priv.Precompute()
	return
}
