package ellipticcurve

import (
	"fmt"
	"github.com/ellemouton/schnorr/finitefield"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestNewPoint(t *testing.T) {
	a, err := finitefield.NewElement(big.NewInt(0), big.NewInt(223))
	require.NoError(t, err)

	b, err := finitefield.NewElement(big.NewInt(7), big.NewInt(223))
	require.NoError(t, err)

	x, err := finitefield.NewElement(big.NewInt(192), big.NewInt(223))
	require.NoError(t, err)

	y, err := finitefield.NewElement(big.NewInt(105), big.NewInt(223))
	require.NoError(t, err)

	curve := NewCurve(a, b)

	p1, err := NewPoint(x, y, curve)
	require.NoError(t, err)

	p2, err := NewPoint(x, y, curve)
	require.NoError(t, err)
	require.True(t, p1.Equal(p2))

	// Test not on curve.
	c, err := finitefield.NewElement(big.NewInt(6), big.NewInt(223))
	require.NoError(t, err)

	curve2 := NewCurve(a, c)
	_, err = NewPoint(x, y, curve2)
	require.Error(t, err)
}

type testPoint struct {
	a int64
	b int64
	x int64
	y int64

	infinity bool
}

func (m *testPoint) ToPoint(t *testing.T, p int64) *Point {
	prime := big.NewInt(p)

	a, err := finitefield.NewElement(big.NewInt(m.a), prime)
	require.NoError(t, err)

	b, err := finitefield.NewElement(big.NewInt(m.b), prime)
	require.NoError(t, err)

	curve := NewCurve(a, b)

	if m.infinity {
		return NewInfinityPoint(curve)
	}

	x, err := finitefield.NewElement(big.NewInt(m.x), prime)
	require.NoError(t, err)

	y, err := finitefield.NewElement(big.NewInt(m.y), prime)
	require.NoError(t, err)

	point, err := NewPoint(x, y, curve)
	require.NoError(t, err)

	return point
}

func TestPointAdd(t *testing.T) {
	tests := []struct {
		p1 testPoint
		p2 testPoint
		p3 testPoint
	}{
		{
			p1: testPoint{a: 0, b: 7, x: 192, y: 105},
			p2: testPoint{a: 0, b: 7, x: 17, y: 56},
			p3: testPoint{a: 0, b: 7, x: 170, y: 142},
		},
		{
			p1: testPoint{a: 0, b: 7, x: 47, y: 71},
			p2: testPoint{a: 0, b: 7, x: 117, y: 141},
			p3: testPoint{a: 0, b: 7, x: 60, y: 139},
		},
		{
			p1: testPoint{a: 0, b: 7, x: 143, y: 98},
			p2: testPoint{a: 0, b: 7, x: 76, y: 66},
			p3: testPoint{a: 0, b: 7, x: 47, y: 71},
		},
		{
			p1: testPoint{a: 0, b: 7, x: 192, y: 105},
			p2: testPoint{a: 0, b: 7, x: 192, y: 105},
			p3: testPoint{a: 0, b: 7, x: 49, y: 71},
		},
		{
			p1: testPoint{a: 0, b: 7, x: 192, y: 105},
			p2: testPoint{a: 0, b: 7, x: 192, y: 105},
			p3: testPoint{a: 0, b: 7, x: 49, y: 71},
		},
		{
			p1: testPoint{a: 0, b: 7, x: 17, y: 56},
			p2: testPoint{a: 0, b: 7, infinity: true},
			p3: testPoint{a: 0, b: 7, x: 17, y: 56},
		},
		{
			p1: testPoint{a: 0, b: 7, x: 17, y: 167},
			p2: testPoint{a: 0, b: 7, x: 17, y: 56},
			p3: testPoint{a: 0, b: 7, infinity: true},
		},
	}

	prime := int64(223)

	for i, test := range tests {
		test := test
		name := fmt.Sprintf("%d", i)

		t.Run(name, func(t *testing.T) {
			p1 := test.p1.ToPoint(t, prime)
			p2 := test.p2.ToPoint(t, prime)
			p3 := test.p3.ToPoint(t, prime)

			p4, err := p1.Add(p2)
			require.NoError(t, err)
			require.True(t, p3.Equal(p4))
		})
	}
}

func TestPointMul(t *testing.T) {
	tests := []struct {
		s  int64
		p1 testPoint
		p2 testPoint
	}{
		{
			s:  2,
			p1: testPoint{a: 0, b: 7, x: 192, y: 105},
			p2: testPoint{a: 0, b: 7, x: 49, y: 71},
		},

		{
			s:  2,
			p1: testPoint{a: 0, b: 7, x: 143, y: 98},
			p2: testPoint{a: 0, b: 7, x: 64, y: 168},
		},
		{
			s:  2,
			p1: testPoint{a: 0, b: 7, x: 47, y: 71},
			p2: testPoint{a: 0, b: 7, x: 36, y: 111},
		},
		{
			s:  4,
			p1: testPoint{a: 0, b: 7, x: 47, y: 71},
			p2: testPoint{a: 0, b: 7, x: 194, y: 51},
		},
		{
			s:  8,
			p1: testPoint{a: 0, b: 7, x: 47, y: 71},
			p2: testPoint{a: 0, b: 7, x: 116, y: 55},
		},
		{
			s:  21,
			p1: testPoint{a: 0, b: 7, x: 47, y: 71},
			p2: testPoint{a: 0, b: 7, infinity: true},
		},
	}

	prime := int64(223)

	for i, test := range tests {
		test := test
		name := fmt.Sprintf("%d", i)

		t.Run(name, func(t *testing.T) {
			p1 := test.p1.ToPoint(t, prime)
			p2 := test.p2.ToPoint(t, prime)

			p3, err := p1.Mul(big.NewInt(test.s))
			require.NoError(t, err)

			require.True(t, p2.Equal(p3))
		})
	}
}
