package musig2

import (
	"fmt"
	"github.com/ellemouton/schnorr"
	"github.com/ellemouton/schnorr/secp256k1"
	"math/big"
)

const PartialSigLen = 32

// PartialSig defines the s value of a single participant of a Musig2 flow.
// Note that unlike a normal Schnorr signature, this signature only has the s
// value and not a public nonce, R. This is because in Musig2, nonce exchange
// must happen first before any party can construct a PartialSig. So at the time
// of partial sig exchange, all participants will already know the public nonces
// meaning that the PartialSig only needs to contain the s value.
type PartialSig struct {
	S *big.Int
}

// NewPartialSig constructs a new PartialSig from the given s.
func NewPartialSig(s *big.Int) (*PartialSig, error) {
	if s.Cmp(secp256k1.N) >= 0 {
		return nil, fmt.Errorf("partial sig out of order bounds")
	}

	return &PartialSig{S: s}, nil
}

// Bytes returns the serialised byte representation of a PartialSig.
func (ps *PartialSig) Bytes() []byte {
	var b [PartialSigLen]byte
	ps.S.FillBytes(b[:])

	return b[:]
}

// ParsePartialSig constructs a PartialSig from the given bytes slice.
func ParsePartialSig(b []byte) (*PartialSig, error) {
	if len(b) != PartialSigLen {
		return nil, fmt.Errorf("wrong len for partial sig")
	}

	var s big.Int
	s.SetBytes(b)

	return NewPartialSig(&s)
}

// Sign produces a valid PartialSig for the given SessionContext, secret key
// and secnonce.
//
//	Let i = the participants index
//	s = R_1i + b*R_2i + e*a*P
//
// NOTE that the signature does not in any way include the tweaks that may have
// been applied to the final aggregated pub key. That is because the tweak is
// added only once to the final aggregated pub key and not once per pub key.
// So the tweak comes in only at the time of aggregating the PartialSigs in
// PartialSigAgg.
func Sign(ctx *SessionContext, sn *SecNonce, sk *schnorr.PrivateKey) (
	*PartialSig, error) {

	signCtx, err := ctx.GetSigContext()
	if err != nil {
		return nil, err
	}

	// If the final schnorr nonce R has an odd Y, then we need to negate
	// our secnonces.
	k1, k2 := sn.k1, sn.k2
	if !signCtx.R.HasEvenY() {
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

	// Get our original (pre coefficients) pub key.
	P := sk.PubKey

	if !sn.pk.Equal(P) {
		return nil, fmt.Errorf("fail")
	}

	// Calculate the coefficient that we applied to the pubkey and hence
	// need to apply to our secret key, sk.
	a, err := keyAggCoeff(ctx.PubKeys, P)
	if err != nil {
		return nil, err
	}

	g := big.NewInt(1)
	if !signCtx.Q.HasEvenY() {
		g.Mod(big.NewInt(-1), secp256k1.N)
	}

	// Negate the private key if needed.
	// 	d' = g * gacc * d
	d := new(big.Int).Mul(new(big.Int).Mul(g, signCtx.GAcc), sk.D)
	d.Mod(d, secp256k1.N)

	// Apply the coefficient to our private key.
	// 	d'' = a * d'
	d.Mul(d, a)

	// r = k1 + b*k2
	r := new(big.Int).Mul(k2.D, signCtx.B)
	r.Add(r, k1.D)

	// ed = e * d''
	ed := new(big.Int).Mul(signCtx.E, d)

	// s = (r + ed) % n
	s := new(big.Int).Add(r, ed)
	s.Mod(s, secp256k1.N)

	ps, err := NewPartialSig(s)
	if err != nil {
		return nil, err
	}

	err = ps.VerifyInternal(ctx, sn.GetPubNonce(), sk.PubKey)
	if err != nil {
		return nil, fmt.Errorf("produced invalid sig")
	}

	return ps, nil
}

// Verify verifies that the PartialSig is valid given the other params.
// NOTE that this is equivalent to PartialSigVerify in the Musig2 spec.
func (ps *PartialSig) Verify(pns []*PubNonce, pks []*schnorr.PublicKey,
	tweaks []*Tweak, msg []byte, i int) error {

	sessionCtx := NewSessionContext(NonceAgg(pns), pks, msg, tweaks)

	err := ps.VerifyInternal(sessionCtx, pns[i], pks[i])
	if err != nil {
		return err
	}

	return nil
}

// VerifyInternal verifies that the PartialSig is valid given the other params.
// NOTE that this is equivalent to PartialSigVerifyInternal in the Musig2 spec.
func (ps *PartialSig) VerifyInternal(ctx *SessionContext, pubNonce *PubNonce,
	pk *schnorr.PublicKey) error {

	signCtx, err := ctx.GetSigContext()
	if err != nil {
		return err
	}

	// Re = R1 + b*R2
	// If the final R has odd Y, then all parties need to negate their
	// individual nonces to get the final Schnorr R to be even Y.
	Re := pubNonce.R1.Add(pubNonce.R2.Mul(signCtx.B))
	if !signCtx.R.HasEvenY() {
		Re = Re.Mul(big.NewInt(-1))
	}

	// Get the coefficient that the pub key should have been tweaked by.
	a, err := keyAggCoeff(ctx.PubKeys, pk)
	if err != nil {
		return err
	}

	g := big.NewInt(1)
	if !signCtx.Q.HasEvenY() {
		g.Mod(big.NewInt(-1), secp256k1.N)
	}

	// g = (g * gacc) %n
	g.Mul(g, signCtx.GAcc)
	g.Mod(g, secp256k1.N)

	S := secp256k1.G.Mul(ps.S)

	// P' = g * e * a * P
	pdash := pk.Mul(g).Mul(signCtx.E).Mul(a)

	// Re + P'
	rightSide := pdash.Add(Re)

	if !S.Equal(rightSide.Point) {
		return fmt.Errorf("fail")
	}

	return nil
}

// PartialSigAgg aggregates the given set of PartialSigs into a single Schnorr
// signature.
func (ctx *SessionContext) PartialSigAgg(psigs []*PartialSig) (
	*schnorr.Signature, error) {

	s := big.NewInt(0)

	for _, psig := range psigs {
		if psig.S.Cmp(secp256k1.N) >= 0 {
			return nil, fmt.Errorf("partial sig out of range")
		}

		s.Add(s, psig.S)
		s.Mod(s, secp256k1.N)
	}

	signCtx, err := ctx.GetSigContext()
	if err != nil {
		return nil, err
	}

	g := big.NewInt(1)
	if !signCtx.Q.HasEvenY() {
		g.Mod(big.NewInt(-1), secp256k1.N)
	}

	c := new(big.Int).Mul(signCtx.E, g)
	c.Mul(c, signCtx.TAcc)

	s.Add(s, c)
	s.Mod(s, secp256k1.N)

	return schnorr.NewSignature(signCtx.R, s)
}
