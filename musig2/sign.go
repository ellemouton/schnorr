package musig2

import (
	"fmt"
	"github.com/ellemouton/schnorr"
	"github.com/ellemouton/schnorr/secp256k1"
	"math/big"
)

type PartialSig [32]byte

func Sign(sn *SecNonce, sk *schnorr.PrivateKey, ctx *SessionContext) (
	*PartialSig, error) {

	keyGenCtx, b, R, e, err := GetSessionValues(ctx)
	if err != nil {
		return nil, err
	}

	k1, k2 := sn.k1, sn.k2
	if !R.HasEvenY() {
		k1, err = schnorr.PrivateKeyFromInt(
			new(big.Int).Sub(secp256k1.N, k1.D),
		)
		if err != nil {
			return nil, err
		}

		k2, err = schnorr.PrivateKeyFromInt(
			new(big.Int).Sub(secp256k1.N, k2.D),
		)
		if err != nil {
			return nil, err
		}
	}

	P := sk.PubKey

	if !sn.pk.Equal(P) {
		return nil, fmt.Errorf("fail")
	}

	a, err := GetSessionKeyAggCoeff(ctx, P)
	if err != nil {
		return nil, err
	}

	g := big.NewInt(1)
	if !keyGenCtx.Q.HasEvenY() {
		g.Mod(big.NewInt(-1), secp256k1.N)
	}

	d := new(big.Int).Mul(new(big.Int).Mul(g, keyGenCtx.GAcc), sk.D)
	d.Mod(d, secp256k1.N)

	// s = (k1 + b⋅k2 + e⋅a⋅d) mod n
	s := big.NewInt(0)
	s.Add(s, k1.D)

	bb := new(big.Int).Mul(k2.D, b)
	s.Add(k1.D, bb)

	ee := new(big.Int).Mul(e, a)
	ee.Mul(ee, d)
	s.Add(s, ee)
	s.Mod(s, secp256k1.N)

	psig := new(PartialSig)
	copy(psig[:], s.Bytes())

	return psig, nil
}
