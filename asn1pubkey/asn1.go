package asn1pubkey

import (
	"bytes"
	"crypto/rsa"
	"math/big"
)

var bigOne = big.NewInt(1)

// This is what crypto/rsa.PublicKey looks like:
// type PublicKey struct {
//         N *big.Int // modulus
//         E int      // public exponent
// }

// Attempt to make a fast version of asn1.Marshal that avoids reflection and
// heap allocation, by hardcoding it to work on just *rsa.PublicKey.
func MarshalPubKey(pk rsa.PublicKey) ([]byte, error) {
	var buf bytes.Buffer
	return asn1EncodePubKey(&buf, pk)
}

// Attempt to make an even faster version, by avoiding allocation of a new
// buffer on the heap. Requires a pre-allocated buffer to be passed for
// re-use purposes.
func MarshalPubKeyFast(buf *bytes.Buffer, pk rsa.PublicKey) ([]byte, error) {
	buf.Reset()
	return asn1EncodePubKey(buf, pk)
}

// Internal method for encoding RSA Public Key as DER asn.1
//
// Expects `buf` to be a primed and ready byte Buffer.
func asn1EncodePubKey(buf *bytes.Buffer, pk rsa.PublicKey) ([]byte, error) {
	var err error

	// ASN.1 SEQUENCE,
	buf.Write([]byte{0x30})
	//  with 2 elements...
	buf.Write([]byte{0x81, 0x89})
	// an integer
	buf.Write([]byte{0x2})
	// ...length 128 bits
	buf.Write([]byte{0x81, 0x81})

	// encode N
	err = marshalBigInt(buf, pk.N)
	if err != nil {
		return nil, err
	}

	// an integer
	buf.Write([]byte{0x2})
	// ...length 3 bits
	buf.Write([]byte{0x3})

	// encode E
	err = marshalInt64(buf, int64(pk.E))
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

/***********************************************************************
  Everything below this point is copy and pasted from Golang source code
  `encoding/asn1/marshal.go`, but *modified* to use simple byte buffers
  in the return signature (no other lines modified).
************************************************************************/

func marshalBigInt(out *bytes.Buffer, n *big.Int) (err error) {
	if n.Sign() < 0 {
		// A negative number has to be converted to two's-complement
		// form. So we'll subtract 1 and invert. If the
		// most-significant-bit isn't set then we'll need to pad the
		// beginning with 0xff in order to keep the number negative.
		nMinus1 := new(big.Int).Neg(n)
		nMinus1.Sub(nMinus1, bigOne)
		bytes := nMinus1.Bytes()
		for i := range bytes {
			bytes[i] ^= 0xff
		}
		if len(bytes) == 0 || bytes[0]&0x80 == 0 {
			err = out.WriteByte(0xff)
			if err != nil {
				return
			}
		}
		_, err = out.Write(bytes)
	} else if n.Sign() == 0 {
		// Zero is written as a single 0 zero rather than no bytes.
		err = out.WriteByte(0x00)
	} else {
		bytes := n.Bytes()
		if len(bytes) > 0 && bytes[0]&0x80 != 0 {
			// We'll have to pad this with 0x00 in order to stop it
			// looking like a negative number.
			err = out.WriteByte(0)
			if err != nil {
				return
			}
		}
		_, err = out.Write(bytes)
	}
	return
}

func marshalInt64(out *bytes.Buffer, i int64) (err error) {
	n := int64Length(i)

	for ; n > 0; n-- {
		err = out.WriteByte(byte(i >> uint((n-1)*8)))
		if err != nil {
			return
		}
	}

	return nil
}

func int64Length(i int64) (numBytes int) {
	numBytes = 1

	for i > 127 {
		numBytes++
		i >>= 8
	}

	for i < -128 {
		numBytes++
		i >>= 8
	}

	return
}
