package ellipticcurve

import (
	"errors"
	"github.com/ellemouton/schnorr/finitefield"
	"math/big"
)

var (
	// ErrPointsNotOnSameCurve is returned when an operation is attempted
	// on two points that are not on the same curve.
	ErrPointsNotOnSameCurve = errors.New("points are not on the same curve")

	// ErrPointNotOnCurve is returned when a given x and y coordinate are
	// not on the given target curve.
	ErrPointNotOnCurve = errors.New("points not on curve")

	one = big.NewInt(1)
)

// Point is a point on a Curve.
type Point struct {
	X *finitefield.Element
	Y *finitefield.Element

	*Curve

	// IsInfinity is true if the coordinate is at infinity. If true,
	// X and Y will be nil and should not be used.
	IsInfinity bool
}

// NewPoint constructs a new Point.
func NewPoint(x, y *finitefield.Element, curve *Curve) (*Point, error) {
	if !curve.Contains(x, y) {
		return nil, ErrPointNotOnCurve
	}

	return &Point{
		X:     x,
		Y:     y,
		Curve: curve,
	}, nil
}

// NewInfinityPoint constructs a new Point at infinity.
func NewInfinityPoint(curve *Curve) *Point {
	return &Point{
		Curve:      curve,
		IsInfinity: true,
	}
}

// Copy returns a copy of the Point.
func (p *Point) Copy() *Point {
	return &Point{
		X:          p.X,
		Y:          p.Y,
		Curve:      p.Curve,
		IsInfinity: p.IsInfinity,
	}
}

// Equal returns true if Points are the same coordinate on the same curve.
func (p *Point) Equal(o *Point) bool {
	if !p.Curve.Equal(o.Curve) {
		return false
	}

	if p.IsInfinity && o.IsInfinity {
		return true
	}

	return p.X.Equal(o.X) && p.Y.Equal(o.Y)
}

// Add adds the two points together.
func (p *Point) Add(o *Point) (*Point, error) {
	if !p.Curve.Equal(o.Curve) {
		return nil, ErrPointsNotOnSameCurve
	}

	if p.IsInfinity {
		return o.Copy(), nil
	}

	if o.IsInfinity {
		return p.Copy(), nil
	}

	if !o.X.Equal(p.X) {
		s1, err := o.Y.Sub(p.Y)
		if err != nil {
			return nil, err
		}

		s2, err := o.X.Sub(p.X)
		if err != nil {
			return nil, err
		}

		s, err := s1.Div(s2)
		if err != nil {
			return nil, err
		}

		t1 := s.Pow(two)

		t2, err := t1.Sub(p.X)
		if err != nil {
			return nil, err
		}

		x3, err := t2.Sub(o.X)
		if err != nil {
			return nil, err
		}

		t3, err := p.X.Sub(x3)
		if err != nil {
			return nil, err
		}

		t4, err := s.Mul(t3)
		if err != nil {
			return nil, err
		}

		y3, err := t4.Sub(p.Y)
		if err != nil {
			return nil, err
		}

		return NewPoint(x3, y3, p.Curve)
	}

	if !o.Y.Equal(p.Y) {
		return NewInfinityPoint(p.Curve), nil
	}

	if o.Y.IsZero() {
		return NewInfinityPoint(p.Curve), nil
	}

	r := p.X.Pow(two)

	r1, err := r.Add(r)
	if err != nil {
		return nil, err
	}

	r2, err := r1.Add(r)
	if err != nil {
		return nil, err
	}

	r3, err := r2.Add(p.A)
	if err != nil {
		return nil, err
	}

	n, err := (p.Y).Add(p.Y)
	if err != nil {
		return nil, err
	}

	s, err := r3.Div(n)
	if err != nil {
		return nil, err
	}

	s2 := s.Pow(two)

	g, err := (p.X).Add(p.X)
	if err != nil {
		return nil, err
	}

	x3, err := s2.Sub(g)
	if err != nil {
		return nil, err
	}

	d, err := p.X.Sub(x3)
	if err != nil {
		return nil, err
	}

	d1, err := s.Mul(d)
	if err != nil {
		return nil, err
	}

	y3, err := d1.Sub(p.Y)
	if err != nil {
		return nil, err
	}

	return NewPoint(x3, y3, p.Curve)
}

// Mul does scalar multiplication on the point.
//
// NOTE: this is vulnerable to the side channel leakage attack described in
//  https://link.springer.com/content/pdf/10.1007/978-3-540-28632-5_14.pdf.
func (p *Point) Mul(c *big.Int) (*Point, error) {
	var coef big.Int
	coef.Set(c)

	current := p.Copy()
	result := NewInfinityPoint(p.Curve)

	var err error
	for coef.Sign() > 0 {
		if new(big.Int).And(&coef, one).Cmp(one) == 0 {
			result, err = result.Add(current)
			if err != nil {
				return nil, err
			}
		}

		current, err = current.Add(current)
		if err != nil {
			return nil, err
		}

		coef.Rsh(&coef, 1)
	}

	return result, nil
}
