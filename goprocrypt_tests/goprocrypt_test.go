package goprocrypt_tests

import (
	"testing"
	"github.com/Yomiji/goprocrypt"
	"github.com/Yomiji/genrsa"
	"time"
	"github.com/golang/protobuf/proto"
)

func TestEncrypt(t *testing.T) {
	testMsg := &TestMsg{
		Time:time.Now().Unix(),
		TrialNo:0,
		Msgtext:"Some Text",
	}
	party1private, _ := genrsa.MakeKeys(2048)
	_, party2public := genrsa.MakeKeys(2048)
	encMsg, err := goprocrypt.Encrypt([]byte("test"), testMsg, party2public, party1private)
	if err != nil || encMsg == nil || len(encMsg.Signature) == 0 || len(encMsg.Digest) == 0 {
		t.Fatalf("Err: %v\nEncMsg:%v\n", err, encMsg)
	}
}

func TestDecrypt(t *testing.T) {
	testMsg := &TestMsg{
		Time:time.Now().Unix(),
		TrialNo:0,
		Msgtext:"Some Text",
	}
	decMsg := &TestMsg{

	}
	party1private, party1public := genrsa.MakeKeys(2048)
	party2private, party2public := genrsa.MakeKeys(2048)
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
	testMsg := &TestMsg{
		Time:time.Now().Unix(),
		TrialNo:0,
		Msgtext:"Some Text",
	}
	decMsg := &TestMsg{

	}
	party1private, party1public := genrsa.MakeKeys(2048)
	party2private, party2public := genrsa.MakeKeys(2048)
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
	testMsg := &TestMsg{
		Time:time.Now().Unix(),
		TrialNo:0,
		Msgtext:"Some Text",
	}
	decMsg := &TestMsg{

	}
	party1private, _ := genrsa.MakeKeys(2048)
	party2private, party2public := genrsa.MakeKeys(2048)
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
	testMsg := &TestMsg{
		Time:time.Now().Unix(),
		TrialNo:0,
		Msgtext:"Some Text",
	}
	decMsg := &TestMsg{

	}
	party1private, party1public := genrsa.MakeKeys(2048)
	_, party2public := genrsa.MakeKeys(2048)
	encMsg, err := goprocrypt.Encrypt([]byte("test"), testMsg, party2public, party1private)
	if err != nil || encMsg == nil || len(encMsg.Signature) == 0 || len(encMsg.Digest) == 0 {
		t.Fatalf("Err: %v\nEncMsg:%v\n", err, encMsg)
	}
	err = goprocrypt.Decrypt([]byte("test"), encMsg, party1private, party1public, decMsg)
	if err == nil {
		t.Fatalf("Err: %v\nEncMsg: %v\nDecMsg: %v\n", err, encMsg, decMsg)
	}
}

