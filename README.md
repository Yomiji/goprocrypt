# goprocrypt
#### Simple Go RSA Asymmetric Key Encryption for Protocol Buffers

### dependency

```bash
dep ensure -add "github.com/Yomiji/goprocrypt"
```


### protocol
Provided EncryptedMessage protocol buffer is returned from an encrypted message. The EncryptedMessage protocol buffer
has the following configuration:
```proto
syntax = "proto3";
package goprocrypt;
option go_package = "goprocrypt";

message EncryptedMessage {
    bytes id = 1; //hash of type
    bytes signature = 3;
    bytes digest = 5;
}
```
The idea is that an application would encrypt, send and then decrypt an EncryptedMessage protocol buffer. An application
could use the id parameter to hash the protocol buffer's specific type.
### useage
```go
import (
	"github.com/Yomiji/genrsa"
	"github.com/Yomiji/goprocrypt"
	"github.com/golang/protobuf/proto"
	"testing"
	"time"
)

var party1private, party1public = genrsa.MakeKeys(2048)
var party2private, party2public = genrsa.MakeKeys(2048)

var testMsg = &TestMsg{
  Time:time.Now().Unix(),
  TrialNo:0,
  Msgtext:"Some Text",
}

func TestEncrypt(t *testing.T) {
	// private key necessary for signature application from first party, encrypting for second party
	encMsg, err := goprocrypt.Encrypt([]byte("test"), testMsg, party2public, party1private)
	
	// do something with encrypted message
}

func TestDecrypt(t *testing.T) {
	decMsg := &TestMsg{}

	encMsg, err := goprocrypt.Encrypt([]byte("test"), testMsg, party2public, party1private)
	
	// first party's public key for verification of identity and second party key for decryption
	// directly modifies decMsg to fill it with the decrypted data, the type must match or an error
	// occurs
	err = goprocrypt.Decrypt([]byte("test"), encMsg, party2private, party1public, decMsg)
	
	// do something with decMsg, which now contains testMsg unencrypted
}
```

To change the encryption algorithm: 
```go
goprocrypt.Hash = crypto.SHA256
```

To change the verification algorithm: 
```go
goprocrypt.Sign = crypto.SHA512_256
```
