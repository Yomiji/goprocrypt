package goprocrypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"math/big"
	"os"

	"github.com/golang/protobuf/proto"
)

/**
From: https://medium.com/@raul_11817/golang-cryptography-rsa-asymmetric-algorithm-e91363a2f7b3
Integrated with protocol buffers for message encryption
go v1.12.4
*/

// Allow the developer to change the hash function
var Hash = crypto.SHA256

// Allow the developer to change the signing function
var Sign = crypto.SHA512_256

// Allow the developer to take logging
var Logger = log.New(os.Stdout, "[GOPROTOCRYPT] ", log.Ldate|log.Ltime)

// Encrypt a protocol buffer 'message' with the given label using the given public key
func Encrypt(label []byte, message proto.Message, publicKey *rsa.PublicKey, privateKeyForSig *rsa.PrivateKey) (encMsg *EncryptedMessage, err error) {
	// handle exceptions
	defer func() {
		if n := recover(); n != nil {
			encMsg = nil
			logErr(n)
		}
	}()
	byteMsg, err := proto.Marshal(message)
	// sign message
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthEqualsHash
	hashed := calculateHash(byteMsg)
	signature, err := rsa.SignPSS(
		rand.Reader,
		privateKeyForSig,
		Sign,
		hashed,
		&opts)
	checkErr(err)
	// encrypt message
	ciphertext, err := rsa.EncryptOAEP(
		Hash.New(),
		rand.Reader,
		publicKey,
		byteMsg,
		label,
	)
	checkErr(err)
	pkey := privateKeyForSig.PublicKey
	return &EncryptedMessage{
		Signature: signature,
		Digest:    ciphertext,
		PublicKey: &PublicKey{
			N: pkey.N.Bytes(),
			E: int32(pkey.E),
		},
	}, err
}

// Decrypt the encrypted message to the given protocol buffer
func Decrypt(label []byte, encryptedMsg *EncryptedMessage, privateKey *rsa.PrivateKey, message proto.Message) (err error) {
	defer func() {
		if n := recover(); n != nil {
			logErr(n)
		}
	}()
	plain, err := rsa.DecryptOAEP(
		Hash.New(),
		rand.Reader,
		privateKey,
		encryptedMsg.Digest,
		label,
	)
	// verify sender
	hashed := calculateHash(plain)
	checkErr(err)
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthEqualsHash
	n := big.NewInt(0)
	n.SetBytes(encryptedMsg.PublicKey.N)
	err = rsa.VerifyPSS(
		&rsa.PublicKey{
			N: n,
			E: int(encryptedMsg.PublicKey.E),
		},
		Sign,
		hashed,
		encryptedMsg.Signature,
		&opts,
	)
	checkErr(err)
	// reconstitute protocol buffer
	err = proto.Unmarshal(plain, message)
	checkErr(err)
	return err
}

func calculateHash(digest []byte) []byte {
	psshMsg := make([]byte, len(digest))
	copy(psshMsg, digest)
	pssh := Sign.New()
	pssh.Write(psshMsg)
	return pssh.Sum(nil)
}

func checkErr(err interface{}) {
	if err != nil {
		panic(err)
	}
}

func logErr(err interface{}) {
	if err != nil && Logger != nil {
		Logger.Println(err)
	}
}
