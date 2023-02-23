package secp256k1

import (
	"github.com/ellemouton/schnorr/ellipticcurve"
	"math/big"
)

var (
	Curve *ellipticcurve.Curve

	A *FieldElement
	B *FieldElement

	zero  = big.NewInt(0)
	seven = big.NewInt(7)
)

func init() {
	fieldInit()

	a, err := NewFieldElement(zero)
	if err != nil {
		panic("error initializing A")
	}
	A = a

	b, err := NewFieldElement(seven)
	if err != nil {
		panic("error initializing B")
	}
	B = b

	Curve = ellipticcurve.NewCurve(a.Element, b.Element)

	pointInit()
}
