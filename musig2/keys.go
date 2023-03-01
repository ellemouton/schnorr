package musig2

import (
	"bytes"
	"fmt"
	"github.com/ellemouton/schnorr"
	"github.com/ellemouton/schnorr/secp256k1"
	"math/big"
	"sort"
)

const (
	KeyAggListTag        = "KeyAgg list"
	KeyAggCoefficientTag = "KeyAgg coefficient"
)

var (
	ErrPointAtInfinity = fmt.Errorf("point at infinity")

	negOne = big.NewInt(-1)
)

// KeySort implements the Musig2 KeySort algorithm. It sorts the given set of
// public keys in lexographical order of their plain pub key bytes.
func KeySort(pks []*schnorr.PublicKey) []*schnorr.PublicKey {
	keys := sortableKeys(pks)
	sort.Sort(keys)

	return keys
}

// KeyGenCtx contains a Public Key Q along with the accumulated tweak that may
// have been applied to Q. It also keeps track of whether the private key
// corresponding to Q will need to be negated before siging.
type KeyGenCtx struct {
	// Q represents the aggregate and potentially tweaked public key.
	Q *schnorr.PublicKey

	// TAcc is the accumulated tweak (0 <= tacc < n)
	TAcc *big.Int

	// GAcc is 1 or -1 mod n. It is used to track the accumulated sign
	// flipping. It indicates whether Q needs to be negated to produce the
	// final x-only result. In other words, it indicates if the private key
	// needs to be negated.
	GAcc *big.Int
}

// ApplyTweak applies the given Tweak to the KeyGenCtx.
func (ctx *KeyGenCtx) ApplyTweak(tweak *Tweak) error {
	// If the tweak is x-only and the current Q has a negative Y, then we
	// set gAcc to -1%n so that we remember to negate the private key
	// correctly at signing time.
	gAcc := big.NewInt(1)
	if tweak.Xonly && !ctx.Q.HasEvenY() {
		gAcc.Mod(negOne, secp256k1.N)
	}

	// Project the tweak only the curve.
	// 	T = t*G
	T := schnorr.NewPublicKey(secp256k1.G.Mul(tweak.T))

	// Q = g*Q + t*G
	//
	// First multiply Q by gAcc. This will negate Q to have an even Y if
	// it currently has an odd Y and if this is an XOnly tweak.
	Q := ctx.Q.Mul(gAcc)

	// New add the tweak.
	Q = Q.Add(T)
	if Q.IsInfinity {
		return ErrPointAtInfinity
	}

	// Add the tweak to the accumulated tweak.
	// Tacc = T + g*Tacc
	tAcc := new(big.Int).Add(tweak.T, new(big.Int).Mul(gAcc, ctx.TAcc))
	tAcc.Mod(tAcc, secp256k1.N)

	ctx.Q = Q
	ctx.TAcc = tAcc
	ctx.GAcc = gAcc

	return nil
}

// KeyAgg aggregates the given set of pub keys into a single one as defined by
// the Musig2 spec. To guard against key cancellation attacks, each pub key is
// multiplied by a coefficient that is dependent on all the pub keys in the set.
func KeyAgg(pks []*schnorr.PublicKey) (*KeyGenCtx, error) {
	pk2, err := getSecondKey(pks)
	if err != nil {
		return nil, fmt.Errorf("could not get second key: %w", err)
	}

	// Initialise a "zero" value Pub key.
	Q := schnorr.NewInfinityPubKey()

	// Iterate over all the pub keys, calculate the coefficient for each
	// and add the pub key multiplied by the coefficient to the aggregate
	// pub key. Note that this means that the private key that each signer
	// will sign with later on will need to be multiplied by the same
	// coefficient.
	//          if      d*G = P
	//          then  c*d*G = cP
	for _, pk := range pks {
		// Compute the coefficient for this pub key that is dependent on
		// all the pub keys in the set.
		coeff := keyAggCoeffInternal(pks, pk, pk2)

		// Compute P' = c*P'
		pkDash := pk.Mul(coeff)

		// Add the result to the aggregate pub key, Q.
		Q = Q.Add(pkDash)
	}

	if Q.IsInfinity {
		return nil, ErrPointAtInfinity
	}

	// Construct a KeyGenCtx. The initial Q is the aggregated pub key.
	// GAcc starts as
	return &KeyGenCtx{
		Q:    Q,
		TAcc: big.NewInt(0),
		GAcc: big.NewInt(1),
	}, nil
}

// getSecondKey returns the plain byte encoding of the second unique key in the
// set. If no second unique key is found then a zero byte array is returned.
func getSecondKey(pks []*schnorr.PublicKey) ([]byte, error) {
	if len(pks) == 0 {
		return nil, fmt.Errorf("must pass at least one key")
	}

	for _, pk := range pks {
		if !pk.Equal(pks[0]) {
			return pk.PlainBytes(), nil
		}
	}

	return bytes.Repeat([]byte{0x0}, 32), nil
}

// keyAggCoeffInternal computes the coefficient that will be applied to pk when
// aggregating the pks.
func keyAggCoeffInternal(pks []*schnorr.PublicKey, pk *schnorr.PublicKey,
	pk2 []byte) *big.Int {

	if bytes.Equal(pk.PlainBytes(), pk2) {
		return big.NewInt(1)
	}

	l := hashKeys(pks)

	b := make([]byte, 32+schnorr.PlainPubKeyBytesLen)
	copy(b[:32], l[:])
	copy(b[32:], pk.PlainBytes())

	return schnorr.IntFromBytes(schnorr.TaggedHash(KeyAggCoefficientTag, b))
}

// keyAggCoeff computes the coefficient that will be applied to pk when
// aggregating the pks.
func keyAggCoeff(pks []*schnorr.PublicKey, pk *schnorr.PublicKey) (*big.Int,
	error) {

	var found bool
	for _, p := range pks {
		if p.Equal(pk) {
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("pub key not found in context list")
	}

	pk2, err := getSecondKey(pks)
	if err != nil {
		return nil, err
	}

	return keyAggCoeffInternal(pks, pk, pk2), nil
}

// hashKeys computes the hash of the pk list.
func hashKeys(pks []*schnorr.PublicKey) [32]byte {
	data := make([]byte, len(pks)*schnorr.PlainPubKeyBytesLen)
	for i, pk := range pks {
		offset1 := i * schnorr.PlainPubKeyBytesLen
		offset2 := offset1 + schnorr.PlainPubKeyBytesLen

		copy(data[offset1:offset2], pk.PlainBytes())
	}

	return schnorr.TaggedHash(KeyAggListTag, data)
}

type sortableKeys []*schnorr.PublicKey

var _ sort.Interface = (*sortableKeys)(nil)

// Len is the number of PublicKeys in the collection.
//
// NOTE: this is part of the sort.Interface interface.
func (s sortableKeys) Len() int {
	return len(s)
}

// Less reports whether the PublicKey with index i must sort before the
// PublicKey with index j.
//
// NOTE: this is part of the sort.Interface interface.
func (s sortableKeys) Less(i, j int) bool {
	return bytes.Compare(s[i].PlainBytes(), s[j].PlainBytes()) < 1
}

// Swap swaps the PublicKeys with indexes i and j.
//
// NOTE: this is part of the sort.Interface interface.
func (s sortableKeys) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
