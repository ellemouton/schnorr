package secp256k1

import (
	"github.com/stretchr/testify/require"
	"testing"
)

// TestBasics shows that the various curve constants behave as expected.
func TestBasics(t *testing.T) {
	// Show that nG = infinity.
	res := G.Mul(N)
	require.True(t, res.IsInfinity)
	require.True(t, res.Equal(NewInfinityPoint()))

	// Show that G is on the curve.
	require.True(t, Curve.Contains(G.X, G.Y))
}
