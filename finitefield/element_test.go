package finitefield

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

// TestElementEqual tests the Equal method of Element.
func TestElementEqual(t *testing.T) {
	tests := []struct {
		num1     int64
		prime1   int64
		num2     int64
		prime2   int64
		expEqual bool
	}{
		{
			num1:     3,
			prime1:   19,
			num2:     3,
			prime2:   19,
			expEqual: true,
		},
		{
			num1:     3,
			prime1:   19,
			num2:     5,
			prime2:   19,
			expEqual: false,
		},
		{
			num1:     3,
			prime1:   19,
			num2:     3,
			prime2:   11,
			expEqual: false,
		},
	}

	for i, test := range tests {
		test := test
		name := fmt.Sprintf("%d", i)
		t.Run(name, func(t *testing.T) {
			f1, err := NewElement(
				big.NewInt(test.num1), big.NewInt(test.prime1),
			)
			require.NoError(t, err)

			f2, err := NewElement(
				big.NewInt(test.num2), big.NewInt(test.prime2),
			)
			require.NoError(t, err)

			require.Equal(t, f1.Equal(f2), f2.Equal(f1))
			require.Equal(t, test.expEqual, f1.Equal(f2))
		})
	}

}

// TestElementAdd tests the Add method of Element.
func TestElementAdd(t *testing.T) {
	f1, err := NewElement(big.NewInt(3), big.NewInt(19))
	require.NoError(t, err)

	f2, err := NewElement(big.NewInt(5), big.NewInt(19))
	require.NoError(t, err)

	f3, err := f1.Add(f2)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(19), f3.p)
	require.Equal(t, big.NewInt(8), f3.Num)

	f4, err := NewElement(big.NewInt(16), big.NewInt(19))
	require.NoError(t, err)

	f5, err := f4.Add(f2)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(19), f5.p)
	require.Equal(t, big.NewInt(2), f5.Num)

	f6, err := NewElement(big.NewInt(3), big.NewInt(11))
	require.NoError(t, err)

	_, err = f6.Add(f1)
	require.Error(t, err)
}

// TestElementSub tests the Sub method of Element.
func TestElementSub(t *testing.T) {
	f1, err := NewElement(big.NewInt(3), big.NewInt(19))
	require.NoError(t, err)

	f2, err := NewElement(big.NewInt(5), big.NewInt(19))
	require.NoError(t, err)

	f3, err := f1.Sub(f2)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(19), f3.p)
	require.Equal(t, big.NewInt(17), f3.Num)

	f4, err := f2.Sub(f1)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(19), f4.p)
	require.Equal(t, big.NewInt(2), f4.Num)

	f5, err := NewElement(big.NewInt(3), big.NewInt(11))
	require.NoError(t, err)

	_, err = f5.Sub(f1)
	require.Error(t, err)
}

func TestMul(t *testing.T) {
	f1, err := NewElement(big.NewInt(24), big.NewInt(31))
	require.NoError(t, err)

	f2, err := NewElement(big.NewInt(19), big.NewInt(31))
	require.NoError(t, err)

	f3, err := NewElement(big.NewInt(22), big.NewInt(31))
	require.NoError(t, err)

	f4, err := f1.Mul(f2)
	require.NoError(t, err)
	require.Equal(t, f3, f4)
}

func TestDiv(t *testing.T) {
	tests := []struct {
		p  int64
		n1 int64
		n2 int64
		n3 int64
	}{
		{p: 19, n1: 2, n2: 7, n3: 3},
		{p: 31, n1: 3, n2: 24, n3: 4},
	}

	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			f1, err := NewElement(
				big.NewInt(test.n1), big.NewInt(test.p),
			)
			require.NoError(t, err)

			f2, err := NewElement(
				big.NewInt(test.n2), big.NewInt(test.p),
			)
			require.NoError(t, err)

			f3, err := NewElement(
				big.NewInt(test.n3), big.NewInt(test.p),
			)
			require.NoError(t, err)

			f4, err := f1.Div(f2)
			require.NoError(t, err)

			require.Equal(t, f3, f4)
		})
	}
}

func TestDiv2(t *testing.T) {
	f1, err := NewElement(big.NewInt(17), big.NewInt(31))
	require.NoError(t, err)

	f2, err := NewElement(big.NewInt(29), big.NewInt(31))
	require.NoError(t, err)

	f3 := f1.Pow(big.NewInt(-3))
	require.Equal(t, f2, f3)

	f4, err := NewElement(big.NewInt(4), big.NewInt(31))
	require.NoError(t, err)

	f5, err := NewElement(big.NewInt(11), big.NewInt(31))
	require.NoError(t, err)

	f6, err := NewElement(big.NewInt(13), big.NewInt(31))
	require.NoError(t, err)

	f7 := f4.Pow(big.NewInt(-4))

	f8, err := f7.Mul(f5)
	require.NoError(t, err)

	require.Equal(t, f6, f8)
}

func TestElementPow(t *testing.T) {
	tests := []struct {
		p  int64
		c  int64
		n1 int64
		n2 int64
	}{
		{p: 13, c: 3, n1: 3, n2: 1},
		{p: 13, c: -3, n1: 7, n2: 8},
		{p: 31, c: 3, n1: 17, n2: 15},
		{p: 31, c: 3, n1: 17, n2: 15},
	}

	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			f1, err := NewElement(
				big.NewInt(test.n1), big.NewInt(test.p),
			)
			require.NoError(t, err)

			f2, err := NewElement(
				big.NewInt(test.n2), big.NewInt(test.p),
			)
			require.NoError(t, err)

			f3 := f1.Pow(big.NewInt(test.c))

			require.Equal(t, f2, f3)
		})
	}
}
