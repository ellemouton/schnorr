package schnorr

import (
	"fmt"
	"github.com/ellemouton/schnorr/secp256k1"
	"math/big"
)

const SignatureSize = 64

// Signature is a schnorr signature.
type Signature struct {
	r *PublicKey
	s *big.Int
}

// NewSignature constructs a new signature.
func NewSignature(r *PublicKey, s *big.Int) (*Signature, error) {
	if s.Cmp(secp256k1.N) >= 0 {
		return nil, fmt.Errorf("invalid s")
	}

	return &Signature{
		r: r,
		s: s,
	}, nil
}

func NewSignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != SignatureSize {
		return nil, fmt.Errorf("wrong sig size")
	}

	R, err := NewPubKeyFromBytes(b[:32])
	if err != nil {
		return nil, err
	}

	var s big.Int
	s.SetBytes(b[32:])

	return NewSignature(R, &s)
}

// Bytes returns the byte representation of the signature.
func (s *Signature) Bytes() [SignatureSize]byte {
	var sig [SignatureSize]byte
	rBytes := s.r.Bytes()
	copy(sig[:32], rBytes[:])
	copy(sig[32:], s.s.Bytes())

	return sig
}

// Verify checks if the signature is a valid schnorr signature for the given
// public key and message.
func (s *Signature) Verify(pk *PublicKey, msg []byte) error {
	pkBytes := pk.Bytes()
	P, err := NewPubKeyFromBytes(pkBytes[:])
	if err != nil {
		return err
	}

	rBytes := s.r.Bytes()
	e := intFromByte(
		TaggedHash(Bip340ChallengeTag, rBytes[:], pkBytes[:], msg),
	)

	one := secp256k1.G.Mul(s.s)
	two := P.Mul(e).Mul(big.NewInt(-1))

	R := NewPublicKey(one.Add(two))

	if !R.HasEvenY() {
		return fmt.Errorf("R does not have even Y")
	}

	if !R.Equal(s.r) {
		return fmt.Errorf("invalid sig")
	}

	return nil
}
