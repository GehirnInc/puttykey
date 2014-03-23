package puttykey

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"
	"strconv"
)

func Marshal(key *rsa.PrivateKey, comment, password string) (ret []byte, err error) {
	output := bytes.NewBufferString("PuTTY-User-Key-File-2: ssh-rsa\r\n")

	// encryption
	output.WriteString("Encryption: ")
	encryption := "none"
	if password != "" {
		encryption = "aes256-cbc"
	}
	output.WriteString(encryption)
	output.WriteString("\r\n")

	// comment
	output.WriteString("Comment: ")
	output.WriteString(comment)
	output.WriteString("\r\n")

	// public
	pub := bytes.NewBuffer(nil)
	binary.Write(pub, binary.BigEndian, uint32(7))
	pub.WriteString("ssh-rsa")

	// E
	E := big.NewInt(int64(key.PublicKey.E)).Bytes()
	binary.Write(pub, binary.BigEndian, uint32(len(E)))
	pub.Write(E)

	// N
	N := key.PublicKey.N.Bytes()
	binary.Write(pub, binary.BigEndian, uint32(len(N)))
	pub.Write(N)

	// compute base64 of public key
	buf := bytes.NewBuffer(nil)
	encoder := base64.NewEncoder(base64.StdEncoding, buf)
	encoder.Write(pub.Bytes())
	encoder.Close()
	encodedPub := buf.Bytes()

	// add output
	output.WriteString("Public-Lines: ")
	output.WriteString(strconv.Itoa((len(encodedPub) + 63) >> 6))
	output.WriteString("\r\n")
	for i := 0; i < len(encodedPub); i += 64 {
		output.Write(encodedPub[i : i+64])
		output.WriteString("\r\n")
	}

	// private
	priv := bytes.NewBuffer(nil)

	// D
	D := key.D.Bytes()
	binary.Write(priv, binary.BigEndian, uint32(len(D)))
	priv.Write(D)

	// P
	P := key.Primes[0].Bytes()
	binary.Write(priv, binary.BigEndian, uint32(len(P)))
	priv.Write(P)

	// Q
	Q := key.Primes[1].Bytes()
	binary.Write(priv, binary.BigEndian, uint32(len(Q)))
	priv.Write(Q)

	// Qinv
	Qinv := key.Precomputed.Qinv.Bytes()
	binary.Write(priv, binary.BigEndian, uint32(len(Qinv)))
	priv.Write(Qinv)

	source := bytes.NewBuffer(nil)
	binary.Write(source, binary.BigEndian, uint32(7))
	source.WriteString("ssh-rsa")
	binary.Write(source, binary.BigEndian, uint32(len(encryption)))
	source.WriteString(encryption)
	binary.Write(source, binary.BigEndian, uint32(len(comment)))
	source.WriteString(comment)
	binary.Write(source, binary.BigEndian, uint32(pub.Len()))
	source.Write(pub.Bytes())

	hashkey := sha1.New()
	if encryption == "none" {
		binary.Write(source, binary.BigEndian, uint32(priv.Len()))
		source.Write(priv.Bytes())

		hashkey.Write([]byte("putty-private-key-file-mac-key"))
	} else {
		random := make([]byte, 16-(priv.Len()&15))
		_, err = io.ReadFull(rand.Reader, random)
		if err != nil {
			return
		}
		priv.Write(random)

		binary.Write(source, binary.BigEndian, uint32(priv.Len()))
		source.Write(priv.Bytes())

		var (
			seq  int
			h    = sha1.New()
			temp = bytes.NewBuffer(nil)

			symkey = bytes.NewBuffer(nil)
		)
		for symkey.Len() < 32 {
			binary.Write(temp, binary.BigEndian, uint32(seq))
			temp.WriteString(password)

			h.Write(temp.Bytes())
			symkey.Write(h.Sum(nil))

			seq++
			h.Reset()
			temp.Reset()
		}

		var block cipher.Block
		block, err = aes.NewCipher(symkey.Bytes()[0:32])
		if err != nil {
			return
		}

		ciphertext := make([]byte, aes.BlockSize+priv.Len())
		iv := ciphertext[:aes.BlockSize]
		_, err = io.ReadFull(rand.Reader, iv)
		if err != nil {
			return
		}

		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(ciphertext[aes.BlockSize:], priv.Bytes())

		priv.Reset()
		priv.Write(ciphertext)

		hashkey.Write([]byte("putty-private-key-file-mac-key" + password))
	}

	// compute base64 of private key
	buf = bytes.NewBuffer(nil)
	encoder = base64.NewEncoder(base64.StdEncoding, buf)
	encoder.Write(priv.Bytes())
	encoder.Close()
	encodedPriv := buf.Bytes()

	// add output
	output.WriteString("Private-Lines: ")
	output.WriteString(strconv.Itoa((len(encodedPriv) + 63) >> 6))
	output.WriteString("\r\n")
	for i := 0; i < len(encodedPriv)/64; i += 1 {
		output.Write(encodedPriv[i*64 : (i+1)*64])
		output.WriteString("\r\n")
	}
	output.Write(encodedPriv[len(encodedPriv)/64*64:])
	output.WriteString("\r\n")

	// add output
	output.WriteString("Private-MAC: ")
	hmacsha1 := hmac.New(sha1.New, hashkey.Sum(nil))
	hmacsha1.Write(source.Bytes())
	output.WriteString(hex.EncodeToString(hmacsha1.Sum(nil)))
	output.WriteString("\r\n")

	ret = output.Bytes()
	return
}
