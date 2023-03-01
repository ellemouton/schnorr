package musig2

import (
	"fmt"
	"github.com/ellemouton/schnorr"
	"github.com/ellemouton/schnorr/secp256k1"
	"math/big"
)

const NonceCoefTag = "MuSig/noncecoef"

var ErrTweakOutOfRange = fmt.Errorf("tweak out of range")

type SessionContext struct {
	// AggPubNonce is the aggregation of all the participants public nonces.
	AggPubNonce *PubNonce

	// PubKeys is the original set of participant Public keys.
	PubKeys []*schnorr.PublicKey

	// Msg is the final message to be signed.
	Msg []byte

	// Tweaks is a list of tweaks (and their modes) that should be applied
	// to the aggregated pub key.
	Tweaks []*Tweak
}

func NewSessionContext(aggNonce *PubNonce, pks []*schnorr.PublicKey, msg []byte,
	tweaks []*Tweak) *SessionContext {

	return &SessionContext{
		AggPubNonce: aggNonce,
		PubKeys:     pks,
		Msg:         msg,
		Tweaks:      tweaks,
	}
}

// SigContext is the info required to both produce a PartialSig and to validate
// a PartialSig.
type SigContext struct {
	*KeyGenCtx
	B *big.Int
	R *schnorr.PublicKey
	E *big.Int
}

// GetSigContext takes a SessionContext and computes all the values needed to
// produce a partial signature. These values are returned in a SigContext. Note
// that in the MuSig2 paper, this method is equivalent to GetSessionValues.
func (ctx *SessionContext) GetSigContext() (*SigContext, error) {
	// Get the initial aggregated public key. The initial tweak is empty
	// and the initial gAcc (sign flip) is 1.
	kgCtx, err := KeyAgg(ctx.PubKeys)
	if err != nil {
		return nil, err
	}

	// Now, apply the given set of tweaks to get the final pub key.
	for _, t := range ctx.Tweaks {
		err = kgCtx.ApplyTweak(t)
		if err != nil {
			return nil, err
		}
	}

	// Compute the b scalar. This will be used to calculate the final
	// aggregated schnorr pub nonce from the two nonces that make up the
	// AggPubNonce.
	//
	// b = H( R1 || R2 || P || m )
	b := schnorr.IntFromBytes(schnorr.TaggedHash(
		NonceCoefTag,
		ctx.AggPubNonce.Bytes(),
		kgCtx.Q.XOnlyBytes(),
		ctx.Msg,
	))

	// Calculate the final, single, Public nonce that will be used to
	// construct the musig signature
	//
	// R = R1 + b*R2
	R := ctx.AggPubNonce.R1.Add(ctx.AggPubNonce.R2.Mul(b))
	if R.IsInfinity {
		R = schnorr.NewPublicKey(secp256k1.G)
	}

	// Finally, construct the e value that commits to the R, P and m values.
	// e = H( R || P || m )
	e := schnorr.IntFromBytes(schnorr.TaggedHash(
		schnorr.Bip340ChallengeTag,
		R.XOnlyBytes(),
		kgCtx.Q.XOnlyBytes(),
		ctx.Msg,
	))

	return &SigContext{
		KeyGenCtx: kgCtx,
		B:         b,
		R:         R,
		E:         e,
	}, nil
}

// Tweak represents a tweak that can be applied to a public key (and private
// key).
//
//		Let P = d*G
//		    P' = P + t*G
//	            d' = d + t
//
// If it is an X-only tweak, then the tweak is applied to liftX(x(P)). In other
// words, if the OG P has an odd Y coordinate, then the tweak is actually
// being applied to the P with the even Y meaning that d' is actually:
//
//	d' = (-d) + t
type Tweak struct {
	T     *big.Int
	Xonly bool
}

// NewTweak constructs a new Tweak from the given byte slice and tweak mode.
func NewTweak(b []byte, xonly bool) (*Tweak, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("tweak must be 32 bytes")
	}

	var t big.Int
	t.SetBytes(b)
	if t.Cmp(secp256k1.N) >= 0 {
		return nil, ErrTweakOutOfRange
	}

	return &Tweak{
		T:     &t,
		Xonly: xonly,
	}, nil
}
