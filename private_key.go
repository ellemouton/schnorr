package schnorr

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"github.com/ellemouton/schnorr/secp256k1"
)

const (
	PrivKeyBytesLen = 32

	Bip340AuxTag       = "BIP0340/aux"
	Bip340NonceTag     = "BIP0340/nonce"
	Bip340ChallengeTag = "BIP0340/challenge"
)

// PrivateKey defines a private key required to create a schnorr signature.
type PrivateKey struct {
	d      *big.Int
	PubKey *PublicKey
}

// NewPrivateKey generates a new random PrivateKey.
func NewPrivateKey() (*PrivateKey, error) {
	d, err := randFieldElement(rand.Reader)
	if err != nil {
		return nil, err
	}

	return newPrivateKey(d)
}

// ParsePrivKeyBytes constructs a new PrivateKey from the given byte slice.
func ParsePrivKeyBytes(sk []byte) (*PrivateKey, error) {
	if len(sk) != PrivKeyBytesLen {
		return nil, fmt.Errorf("incorrect number of byte")
	}

	var d big.Int
	d.SetBytes(sk)

	return newPrivateKey(&d)
}

// ParsePrivKeyHexString constructs a new PrivateKey from the given hex string.
func ParsePrivKeyHexString(s string) (*PrivateKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return ParsePrivKeyBytes(b)
}

// newPrivateKey creates a new PrivateKey from the given secret key.
func newPrivateKey(d *big.Int) (*PrivateKey, error) {
	if d.Sign() <= 0 || d.Cmp(secp256k1.N) > 0 {
		return nil, fmt.Errorf("invalid private key generated")
	}

	return &PrivateKey{
		d:      d,
		PubKey: NewPublicKey(secp256k1.G.Mul(d)),
	}, nil
}

// Bytes returns the 32 byte representation of the private key.
func (p *PrivateKey) Bytes() [PrivKeyBytesLen]byte {
	return skBytes(p.d)
}

// Sign uses the PrivateKey to sign the given message and produce a valid
// Signature.
func (p *PrivateKey) Sign(msg, aux []byte) (*Signature, error) {
	if len(msg) != 32 || len(aux) != 32 {
		return nil, fmt.Errorf("msg and aux must have len 32")
	}

	// Make a copy of the secret key.
	// 	Let d' = int(sk)
	var d big.Int
	d.Add(p.d, big.NewInt(0))

	// Negate the secret key if the public key has an odd Y.
	// 	Let d = d' if has_even_y(P), otherwise let d = n - d'
	if !p.PubKey.HasEvenY() {
		d.Sub(secp256k1.N, &d)
	}

	// Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a)
	t := xor(skBytes(&d), TaggedHash(Bip340AuxTag, aux[:]))

	// Let rand = hashBIP0340/nonce(t || bytes(P) || m)
	pBytes := p.PubKey.Bytes()
	rand := TaggedHash(Bip340NonceTag, t[:], pBytes[:], msg[:])

	// Let k' = int(rand) mod n
	k := intFromByte(rand)

	// Fail if k' = 0.
	if k.Sign() == 0 {
		return nil, fmt.Errorf("failed to sign with zero value k")
	}

	// Let R = k'⋅G.
	R := NewPublicKey(secp256k1.G.Mul(k))

	// Let k = k' if has_even_y(R), otherwise let k = n - k'.
	if !R.HasEvenY() {
		k.Sub(secp256k1.N, k)
	}

	// Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n
	rBytes := R.Bytes()
	e := intFromByte(
		TaggedHash(Bip340ChallengeTag, rBytes[:], pBytes[:], msg),
	)

	s := k.Mod(k.Add(k, e.Mul(e, &d)), secp256k1.N)

	sig, err := NewSignature(R, s)
	if err != nil {
		return nil, err
	}

	// Verify here.

	return sig, nil
}

// randFieldElement returns a random element of the order of the secp256k1
// curve.
//
// NOTE: this is copied from /usr/local/go/src/crypto/ecdsa/ecdsa_legacy.go.
func randFieldElement(rand io.Reader) (*big.Int, error) {
	var (
		N   = secp256k1.N
		k   big.Int
		err error
	)
	for {
		b := make([]byte, (N.BitLen()+7)/8)
		if _, err = io.ReadFull(rand, b); err != nil {
			return nil, err
		}
		if excess := len(b)*8 - N.BitLen(); excess > 0 {
			b[0] >>= excess
		}
		k.SetBytes(b)
		if k.Sign() != 0 && k.Cmp(N) < 0 {
			break
		}
	}

	return &k, err
}

func skBytes(d *big.Int) [32]byte {
	var b [32]byte
	d.FillBytes(b[:])

	return b
}

func xor(a, b [32]byte) [32]byte {
	var c [32]byte
	for i := range c {
		c[i] = a[i] ^ b[i]
	}

	return c
}

func intFromByte(b [32]byte) *big.Int {
	var res big.Int
	res.SetBytes(b[:])
	res.Mod(&res, secp256k1.N)

	return &res
}
