package secp256k1

import (
	"github.com/ellemouton/schnorr/finitefield"
	"math/big"
)

// P is the prime of the secp256k1 finite field.
var P *big.Int

const p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"

// FieldElement is an secp256k1 Element.
type FieldElement struct {
	*finitefield.Element
}

// NewFieldElement constructs a new FieldElement.
func NewFieldElement(n *big.Int) (*FieldElement, error) {
	e, err := finitefield.NewElement(n, P)
	if err != nil {
		return nil, err
	}

	return &FieldElement{e}, nil
}

// Equal returns true if the passed Element is equivalent to this Element.
func (e *FieldElement) Equal(o *FieldElement) bool {
	return e.Element.Equal(o.Element)
}

// Add adds two Elements in the same finite field together.
func (e *FieldElement) Add(o *FieldElement) (*FieldElement, error) {
	res, err := e.Element.Add(o.Element)
	if err != nil {
		return nil, err
	}

	return &FieldElement{res}, nil
}

// Sub subtracts the given Element from this Element.
func (e *FieldElement) Sub(o *FieldElement) (*FieldElement, error) {
	res, err := e.Element.Sub(o.Element)
	if err != nil {
		return nil, err
	}

	return &FieldElement{res}, nil
}

// Mul multiplies the two Elements together.
func (e *FieldElement) Mul(o *FieldElement) (*FieldElement, error) {
	res, err := e.Element.Mul(o.Element)
	if err != nil {
		return nil, err
	}

	return &FieldElement{res}, nil
}

// Pow defines exponentiation on the Element.
func (e *FieldElement) Pow(exp *big.Int) *FieldElement {
	res := e.Element.Pow(exp)

	return &FieldElement{res}
}

// Div divides this FieldElement by the given FieldElement and returns the
// resulting FieldElement.
func (e *FieldElement) Div(o *FieldElement) (*FieldElement, error) {
	res, err := e.Element.Div(o.Element)
	if err != nil {
		return nil, err
	}

	return &FieldElement{res}, nil
}

// IsZero returns true if the FieldElement's number is zero.
func (e *FieldElement) IsZero() bool {
	return e.Element.IsZero()
}

func fieldInit() {
	var ok bool
	P, ok = new(big.Int).SetString(p, 16)
	if !ok {
		panic("invalid hex: " + p)
	}
}
