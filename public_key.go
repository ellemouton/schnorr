package schnorr

import (
	"encoding/hex"
	"fmt"
	"github.com/ellemouton/schnorr/secp256k1"
	"math/big"
)

const PubKeyBytesLen = 32

// PublicKey is a public key.
type PublicKey struct {
	*secp256k1.Point
}

// NewPublicKey constructs a new Public key from the given secp256k1 point.
func NewPublicKey(p *secp256k1.Point) *PublicKey {
	return &PublicKey{p}
}

// NewInfinityPubKey constructs a new PublicKey at infinity. This is effectively
// a zero value PublicKey.
func NewInfinityPubKey() *PublicKey {
	return &PublicKey{secp256k1.NewInfinityPoint()}
}

// NewPubKeyFromHexString constructs a new PublicKey from the passed hex string.
func NewPubKeyFromHexString(s string) (*PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return NewPubKeyFromBytes(b)
}

// NewPubKeyFromBytes constructs a new PublicKey from the passed bytes slice.
func NewPubKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != PubKeyBytesLen {
		return nil, fmt.Errorf("incorrect number of bytes for pub key")
	}

	var xInt big.Int
	xInt.SetBytes(b)

	x, err := secp256k1.NewFieldElement(&xInt)
	if err != nil {
		return nil, err
	}

	seven, err := secp256k1.NewFieldElement(big.NewInt(7))
	if err != nil {
		return nil, err
	}

	c, err := x.Pow(big.NewInt(3)).Add(seven)
	if err != nil {
		return nil, err
	}

	var exp big.Int
	exp.Add(secp256k1.P, big.NewInt(1))
	exp.Div(&exp, big.NewInt(4))

	y := c.Pow(&exp)

	y2, err := y.Mul(y)
	if err != nil {
		return nil, err
	}

	if !y2.Equal(c) {
		return nil, fmt.Errorf("could not lift x")
	}

	// Make sure that the point returned has an even Y value.
	if y.Num.Bit(0) != 0 {
		y.Num.Sub(secp256k1.P, y.Num)
	}

	p, err := secp256k1.NewPoint(x, y)
	if err != nil {
		return nil, err
	}

	return NewPublicKey(p), nil
}

// Bytes returns the 32 byte representation of the Public key.
func (p *PublicKey) Bytes() [PubKeyBytesLen]byte {
	var b [PubKeyBytesLen]byte
	p.X.Num.FillBytes(b[:])

	return b
}

// HasEvenY returns true if the public key'S Y coordinate is even.
func (p *PublicKey) HasEvenY() bool {
	if p.IsInfinity {
		return true
	}

	return p.Y.Num.Bit(0) == 0
}

// Copy returns a new copy of the PublicKey.
func (p *PublicKey) Copy() *PublicKey {
	return &PublicKey{p.Point.Copy()}
}

// Equal returns true if the two PublicKeys are the same.
func (p *PublicKey) Equal(o *PublicKey) bool {
	if p.IsInfinity || o.IsInfinity {
		return p.IsInfinity && o.IsInfinity
	}

	return p.X.Equal(o.X)
}

// Add adds the two PublicKey points and returns the result.
func (p *PublicKey) Add(o *PublicKey) *PublicKey {
	return &PublicKey{p.Point.Add(o.Point)}
}

// Mul multiplies the Public key with the given constant and returns the result.
func (p *PublicKey) Mul(c *big.Int) *PublicKey {
	return &PublicKey{p.Point.Mul(c)}
}
