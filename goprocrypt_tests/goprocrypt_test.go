package goprocrypt_tests

import (
	"github.com/Yomiji/genrsa"
	"github.com/Yomiji/goprocrypt"
	"github.com/golang/protobuf/proto"
	"testing"
	"time"
)

var testMsg = &TestMsg{
Time:time.Now().Unix(),
TrialNo:0,
Msgtext:"Some Text",
}

var party1private, party1public = genrsa.MakeKeys(2048)
var party2private, party2public = genrsa.MakeKeys(2048)

func TestEncrypt(t *testing.T) {
	encMsg, err := goprocrypt.Encrypt([]byte("test"), testMsg, party2public, party1private)
	if err != nil || encMsg == nil || len(encMsg.Signature) == 0 || len(encMsg.Digest) == 0 {
		t.Fatalf("Err: %v\nEncMsg:%v\n", err, encMsg)
	}
}

func TestDecrypt(t *testing.T) {
	decMsg := &TestMsg{}

	encMsg, err := goprocrypt.Encrypt([]byte("test"), testMsg, party2public, party1private)
	if err != nil || encMsg == nil || len(encMsg.Signature) == 0 || len(encMsg.Digest) == 0 {
		t.Fatalf("Err: %v\nEncMsg:%v\n", err, encMsg)
	}
	err = goprocrypt.Decrypt([]byte("test"), encMsg, party2private, party1public, decMsg)
	if err != nil || !proto.Equal(testMsg, decMsg) {
		t.Fatalf("Err: %v\nEncMsg: %v\nDecMsg: %v\n", err, encMsg, decMsg)
	}
}

func TestDecryptBadLabel(t *testing.T) {
	decMsg := &TestMsg{}

	encMsg, err := goprocrypt.Encrypt([]byte("test"), testMsg, party2public, party1private)
	if err != nil || encMsg == nil || len(encMsg.Signature) == 0 || len(encMsg.Digest) == 0 {
		t.Fatalf("Err: %v\nEncMsg:%v\n", err, encMsg)
	}
	err = goprocrypt.Decrypt([]byte("not a test label"), encMsg, party2private, party1public, decMsg)
	if err == nil {
		t.Fatalf("Err: %v\nEncMsg: %v\nDecMsg: %v\n", err, encMsg, decMsg)
	}
}

func TestDecryptBadPublicKey(t *testing.T) {
	decMsg := &TestMsg{}

	encMsg, err := goprocrypt.Encrypt([]byte("test"), testMsg, party2public, party1private)
	if err != nil || encMsg == nil || len(encMsg.Signature) == 0 || len(encMsg.Digest) == 0 {
		t.Fatalf("Err: %v\nEncMsg:%v\n", err, encMsg)
	}
	err = goprocrypt.Decrypt([]byte("test"), encMsg, party2private, party2public, decMsg)
	if err == nil {
		t.Fatalf("Err: %v\nEncMsg: %v\nDecMsg: %v\n", err, encMsg, decMsg)
	}
}

func TestDecryptBadPrivateKey(t *testing.T) {
	decMsg := &TestMsg{}

	encMsg, err := goprocrypt.Encrypt([]byte("test"), testMsg, party2public, party1private)
	if err != nil || encMsg == nil || len(encMsg.Signature) == 0 || len(encMsg.Digest) == 0 {
		t.Fatalf("Err: %v\nEncMsg:%v\n", err, encMsg)
	}
	err = goprocrypt.Decrypt([]byte("test"), encMsg, party1private, party1public, decMsg)
	if err == nil {
		t.Fatalf("Err: %v\nEncMsg: %v\nDecMsg: %v\n", err, encMsg, decMsg)
	}
}

