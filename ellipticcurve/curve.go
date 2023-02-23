package ellipticcurve

import (
	"github.com/ellemouton/schnorr/finitefield"
	"math/big"
)

var (
	two   = big.NewInt(2)
	three = big.NewInt(3)
)

// Curve is an elliptic curve. It is a curve that satisfies the equation:
//
//	y^2 = x^3 + ax + b
//
// Thus it is parameterised by its coefficients A and B.
type Curve struct {
	A *finitefield.Element
	B *finitefield.Element
}

// NewCurve constructs a new Curve.
func NewCurve(a, b *finitefield.Element) *Curve {
	return &Curve{
		A: a,
		B: b,
	}
}

// Contains returns true if the curve contains the given coordinates.
func (c *Curve) Contains(x, y *finitefield.Element) bool {
	t1 := y.Pow(two)
	t2 := x.Pow(three)

	t3, err := c.A.Mul(x)
	if err != nil {
		return false
	}

	t4, err := t2.Add(t3)
	if err != nil {
		return false
	}

	t5, err := t4.Add(c.B)
	if err != nil {
		return false
	}

	return t1.Equal(t5)
}

// Equal returns true if the two Curves are the same.
func (c *Curve) Equal(o *Curve) bool {
	return c.A.Equal(o.A) && c.B.Equal(o.B)
}
