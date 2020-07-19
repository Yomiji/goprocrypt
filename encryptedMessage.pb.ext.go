package goprocrypt

import (
	"crypto/rsa"
	"math/big"
)

func RsaKeyToPbKey(pkey rsa.PublicKey) *PublicKey {
	return &PublicKey{
		N: pkey.N.Bytes(),
		E: int32(pkey.E),
	}
}

func PbKeyToRsaKey(pbKey *PublicKey) *rsa.PublicKey {
	n := big.NewInt(0)
	n.SetBytes(pbKey.N)
	return &rsa.PublicKey{
		N: n,
		E: int(pbKey.E),
	}
}