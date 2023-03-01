package finitefield

import (
	"errors"
	"fmt"
	"math/big"
)

var (
	one = big.NewInt(1)
	two = big.NewInt(2)

	ErrElementsOfDifferentFields = errors.New("elements must be in the " +
		"same finite field")
)

// Element is an item in a finite field. An Element can only interact with other
// elements that are in the same finite field. A finite field is parameterized
// by its _order_. The order of a field is always greater than 1 and is always
// a power of a prime.
type Element struct {
	// Num is the Element's number in its finite field. This number must be
	// more than 0 and less than P.
	Num *big.Int

	// P is the order of the finite field in which the Element's Num is
	// defined.
	P *big.Int
}

// NewElement constructs a new Element.
func NewElement(n, p *big.Int) (*Element, error) {
	if n.Sign() < 0 {
		return nil, fmt.Errorf("the element cannot be negative")
	}

	if n.Cmp(p) >= 0 {
		return nil, fmt.Errorf("the element must be less than the " +
			"order")
	}

	return &Element{
		Num: n,
		P:   p,
	}, nil
}

// String returns a string representation of Element.
func (e *Element) String() string {
	return fmt.Sprintf("Element_%s(%s)", e.P, e.Num)
}

// Equal returns true if the passed Element is equivalent to this Element.
func (e *Element) Equal(o *Element) bool {
	// Elements in different finite fields are not equal.
	if e.P.Cmp(o.P) != 0 {
		return false
	}

	return e.Num.Cmp(o.Num) == 0
}

// Add adds two Elements in the same finite field together.
func (e *Element) Add(o *Element) (*Element, error) {
	if e.P.Cmp(o.P) != 0 {
		return nil, ErrElementsOfDifferentFields
	}

	var res big.Int
	res.Add(e.Num, o.Num)
	res.Mod(&res, e.P)

	return &Element{
		Num: &res,
		P:   e.P,
	}, nil
}

// Sub subtracts the given Element from this Element.
func (e *Element) Sub(o *Element) (*Element, error) {
	if e.P.Cmp(o.P) != 0 {
		return nil, ErrElementsOfDifferentFields
	}

	var res big.Int
	res.Sub(e.Num, o.Num)
	res.Mod(&res, e.P)

	if res.Sign() < 0 {
		res.Add(&res, e.P)
	}

	return &Element{
		Num: &res,
		P:   e.P,
	}, nil
}

// Mul multiplies the two Elements together.
func (e *Element) Mul(o *Element) (*Element, error) {
	if e.P.Cmp(o.P) != 0 {
		return nil, ErrElementsOfDifferentFields
	}

	var res big.Int
	res.Mul(e.Num, o.Num)
	res.Mod(&res, e.P)

	if res.Sign() < 0 {
		res.Add(&res, e.P)
	}

	return &Element{
		Num: &res,
		P:   e.P,
	}, nil
}

// Pow defines exponentiation on the Element.
func (e *Element) Pow(exp *big.Int) *Element {
	var p big.Int
	p.Sub(e.P, one)

	var n big.Int
	n.Mod(exp, &p)

	if n.Sign() < 0 {
		n.Add(&n, &p)
	}

	var res big.Int
	res.Exp(e.Num, &n, e.P)

	if res.Sign() < 0 {
		res.Add(&res, e.P)
	}

	return &Element{
		Num: &res,
		P:   e.P,
	}
}

// Div divides this Element by the given Element and returns the resulting
// Element.
func (e *Element) Div(o *Element) (*Element, error) {
	if e.P.Cmp(o.P) != 0 {
		return nil, ErrElementsOfDifferentFields
	}

	var exp big.Int
	exp.Sub(e.P, two)

	n2, err := e.Mul(o.Pow(&exp))
	if err != nil {
		return nil, err
	}

	return n2, nil
}

// IsZero returns true if the Element's number is zero.
func (e *Element) IsZero() bool {
	return e.Num.Sign() == 0
}
