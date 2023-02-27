package schnorr

import (
	"fmt"
	"github.com/ellemouton/schnorr/secp256k1"
	"math/big"
)

const SignatureSize = 64

// Signature is a schnorr signature.
type Signature struct {
	R *PublicKey
	S *big.Int
}

// NewSignature constructs a new signature.
func NewSignature(r *PublicKey, s *big.Int) (*Signature, error) {
	if s.Cmp(secp256k1.N) >= 0 {
		return nil, fmt.Errorf("invalid S")
	}

	return &Signature{
		R: r,
		S: s,
	}, nil
}

func NewSignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != SignatureSize {
		return nil, fmt.Errorf("wrong sig size")
	}

	R, err := ParseXOnlyPubKey(b[:32])
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
	copy(sig[:32], s.R.XOnlyBytes()[:])
	copy(sig[32:], s.S.Bytes())

	return sig
}

// Verify checks if the signature is a valid schnorr signature for the given
// public key and message.
func (s *Signature) Verify(pk *PublicKey, msg []byte) error {
	pkBytes := pk.XOnlyBytes()
	P, err := ParseXOnlyPubKey(pkBytes[:])
	if err != nil {
		return err
	}

	e := intFromByte(
		TaggedHash(
			Bip340ChallengeTag, s.R.XOnlyBytes()[:], pkBytes[:],
			msg,
		),
	)

	one := NewPublicKey(secp256k1.G.Mul(s.S))
	two := P.Mul(e).Mul(big.NewInt(-1))

	R := one.Add(two)

	if !R.HasEvenY() {
		return fmt.Errorf("R does not have even Y")
	}

	if !R.Equal(s.R) {
		return fmt.Errorf("invalid sig")
	}

	return nil
}

// BatchVerify does batch schnorr verification of the given set of pubkeys,
// messages and signatures.
//
// NOTE: this currently is not secure since the coefficients have not been
// applied yet and so is subject to a cancellation attack.
// TODO(elle): add the coefficients.
func BatchVerify(pks []*PublicKey, msgs [][]byte, sigs []*Signature) error {
	if len(pks) != len(msgs) || len(pks) != len(sigs) {
		return fmt.Errorf("same number of pub keys, messages and " +
			"sigs must be passed in")
	}

	// S = R + ed
	// S = R + eP
	// (s1+s2+s3+...)*G =? (R1+R2+R3+...) + (e1P1+e2P2+e3P3+...)
	var (
		sAcc  = new(big.Int)
		rAcc  = NewInfinityPubKey()
		epAcc = NewInfinityPubKey()
	)
	for i, sig := range sigs {
		e := intFromByte(TaggedHash(
			Bip340ChallengeTag, sig.R.XOnlyBytes()[:],
			pks[i].XOnlyBytes()[:], msgs[i],
		))

		epAcc = epAcc.Add(pks[i].Mul(e))
		rAcc = rAcc.Add(sig.R)
		sAcc.Add(sAcc, sig.S)
	}

	S := NewPublicKey(secp256k1.G.Mul(sAcc))

	if S.Equal(rAcc.Add(epAcc)) {
		return nil
	}

	return fmt.Errorf("batch verification failed")
}
