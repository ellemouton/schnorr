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

// KeySort implements the Musig2 KeySort algorithm. It sorts the given set of
// public keys in lexographical order of their plain pub key bytes.
func KeySort(pks []*schnorr.PublicKey) []*schnorr.PublicKey {
	keys := sortableKeys(pks)
	sort.Sort(keys)

	return keys
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

type KeyGenCtx struct {
	// Q represents the aggregate and potentially tweaked public key.
	Q *schnorr.PublicKey

	// TAcc is the accumulated tweak (0 <= tacc < n)
	TAcc *big.Int

	// GAcc is 1 or -1 mod n
	GAcc *big.Int
}

// ApplyTweak implements the musig2 ApplyTweak algorithm. The given tweak is
// applied to the given context in the specified mode and the resulting
// KeyGenCtx is returned
func ApplyTweak(ctx *KeyGenCtx, tweak []byte, isXOnlyTweak bool) (*KeyGenCtx,
	error) {

	if len(tweak) != 32 {
		return nil, fmt.Errorf("tweak must be 32 bytes")
	}

	gAcc := big.NewInt(1)
	if isXOnlyTweak && !ctx.Q.HasEvenY() {
		gAcc.Mod(big.NewInt(-1), secp256k1.N)
	}

	var t big.Int
	t.SetBytes(tweak[:])
	if t.Cmp(secp256k1.N) >= 0 {
		return nil, fmt.Errorf("tweak out of range")
	}

	// Q_i = g*Q + t*G
	Q := ctx.Q.Mul(gAcc)
	Q = Q.Add(schnorr.NewPublicKey(secp256k1.G.Mul(&t)))
	if Q.IsInfinity {
		return nil, fmt.Errorf("point at infinity")
	}

	tAcc := new(big.Int).Add(&t, new(big.Int).Mul(gAcc, ctx.TAcc))
	tAcc.Mod(tAcc, secp256k1.N)

	return &KeyGenCtx{
		Q:    Q,
		TAcc: tAcc,
		GAcc: gAcc,
	}, nil
}

// KeyAgg aggregates the given set of pub keys into a single one as defined
// by the Musig2 spec.
func KeyAgg(pks []*schnorr.PublicKey) (*KeyGenCtx, error) {
	pk2, err := GetSecondKey(pks)
	if err != nil {
		return nil, fmt.Errorf("could not get second key: %w", err)
	}

	Q := schnorr.NewInfinityPubKey()
	for _, pk := range pks {
		Q = Q.Add(pk.Mul(KeyAggCoeffInternal(pks, pk, pk2)))
	}

	if Q.IsInfinity {
		return nil, fmt.Errorf("final pub key cannot be infinity")
	}

	return &KeyGenCtx{
		Q:    Q,
		TAcc: big.NewInt(0),
		GAcc: big.NewInt(1),
	}, nil
}

// GetSecondKey returns the plain byte encoding of the second unique key in the
// set. If no second unique key is found then a zero byte array is returned.
func GetSecondKey(pks []*schnorr.PublicKey) ([]byte, error) {
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

func KeyAggCoeffInternal(pks []*schnorr.PublicKey, pk *schnorr.PublicKey,
	pk2 []byte) *big.Int {

	if bytes.Equal(pk.PlainBytes(), pk2) {
		return big.NewInt(1)
	}

	l := HashKeys(pks)

	b := make([]byte, 32+schnorr.PlainPubKeyBytesLen)
	copy(b[:32], l[:])
	copy(b[32:], pk.PlainBytes())

	return schnorr.IntFromBytes(schnorr.TaggedHash(KeyAggCoefficientTag, b))
}

func KeyAggCoeff(pks []*schnorr.PublicKey, pk *schnorr.PublicKey) (*big.Int,
	error) {

	pk2, err := GetSecondKey(pks)
	if err != nil {
		return nil, err
	}

	return KeyAggCoeffInternal(pks, pk, pk2), nil
}

func HashKeys(pks []*schnorr.PublicKey) [32]byte {
	data := make([]byte, len(pks)*schnorr.PlainPubKeyBytesLen)
	for i, pk := range pks {
		offset1 := i * schnorr.PlainPubKeyBytesLen
		offset2 := offset1 + schnorr.PlainPubKeyBytesLen

		copy(data[offset1:offset2], pk.PlainBytes())
	}

	return schnorr.TaggedHash(KeyAggListTag, data)
}
