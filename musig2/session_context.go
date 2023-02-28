package musig2

import (
	"fmt"
	"github.com/ellemouton/schnorr"
	"github.com/ellemouton/schnorr/secp256k1"
	"math/big"
)

const NonceCoefTag = "MuSig/noncecoef"

type SessionContext struct {
	AggPubNonce *PubNonce
	PubKeys     []*schnorr.PublicKey
	Msg         []byte
	Tweaks      []*Tweak
}

func GetSessionValues(ctx *SessionContext) (*KeyGenCtx, *big.Int,
	*schnorr.PublicKey, *big.Int, error) {

	kgCtx, err := KeyAgg(ctx.PubKeys)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	for _, t := range ctx.Tweaks {
		kgCtx, err = ApplyTweak(kgCtx, t.T[:], t.Xonly)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	b := schnorr.IntFromBytes(schnorr.TaggedHash(
		NonceCoefTag, ctx.AggPubNonce.Bytes(), kgCtx.Q.XOnlyBytes(),
		ctx.Msg,
	))

	R := ctx.AggPubNonce.R1.Add(ctx.AggPubNonce.R2.Mul(b))
	if R.IsInfinity {
		R = schnorr.NewPublicKey(secp256k1.G)
	}

	e := schnorr.IntFromBytes(schnorr.TaggedHash(
		schnorr.Bip340ChallengeTag, R.XOnlyBytes(),
		kgCtx.Q.XOnlyBytes(), ctx.Msg,
	))

	return kgCtx, b, R, e, nil
}

func GetSessionKeyAggCoeff(ctx *SessionContext, pk *schnorr.PublicKey) (
	*big.Int, error) {

	var found bool
	for _, p := range ctx.PubKeys {
		if p.Equal(pk) {
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("pub key not found in context list")
	}

	return KeyAggCoeff(ctx.PubKeys, pk)
}

type Tweak struct {
	T     [32]byte
	Xonly bool
}

func NewTweak(b []byte, xonly bool) (*Tweak, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("tweak must be 32 bytes")
	}

	var t [32]byte
	copy(t[:], b)

	return &Tweak{
		T:     t,
		Xonly: xonly,
	}, nil
}
