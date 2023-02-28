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

func PartialSigVerify(psig *PartialSig, pns []*PubNonce,
	pks []*schnorr.PublicKey, tweaks []*Tweak, msg []byte, i int) error {

	sessionCtx := &SessionContext{
		AggPubNonce: NonceAgg(pns),
		PubKeys:     pks,
		Msg:         msg,
		Tweaks:      tweaks,
	}

	err := PartialSigVerifyInternal(psig, pns[i], pks[i], sessionCtx)
	if err != nil {
		return err
	}

	return nil
}

func PartialSigVerifyInternal(psig *PartialSig, pubNonce *PubNonce,
	pk *schnorr.PublicKey, sessCtx *SessionContext) error {

	keyGenCtx, b, R, e, err := GetSessionValues(sessCtx)
	if err != nil {
		return err
	}

	var s big.Int
	s.SetBytes(psig[:])

	if s.Cmp(secp256k1.N) >= 0 {
		return fmt.Errorf("psig out of bounds")
	}

	Re := pubNonce.R1.Add(pubNonce.R2.Mul(b))
	if !R.HasEvenY() {
		Re = Re.Mul(big.NewInt(-1))
	}

	a, err := GetSessionKeyAggCoeff(sessCtx, pk)
	if err != nil {
		return err
	}

	g := big.NewInt(1)
	if !keyGenCtx.Q.HasEvenY() {
		g.Mod(big.NewInt(-1), secp256k1.N)
	}

	g.Mul(g, keyGenCtx.GAcc)
	g.Mod(g, secp256k1.N)

	S := secp256k1.G.Mul(&s)

	pk = pk.Mul(g).Mul(e).Mul(a)
	pk = pk.Add(Re)

	if !S.Equal(pk.Point) {
		return fmt.Errorf("fail")
	}

	return nil
}
