package musig2

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/ellemouton/schnorr"
	"math"
)

const (
	AuxTag   = "MuSig/aux"
	NonceTag = "MuSig/nonce"

	SecNonceLen = 97 // 32 + 32 + 33
	PubNonceLen = 66 // 33 + 33
)

var zeroByteVector = bytes.Repeat([]byte{0x00}, 33)

// NonceGenOption defines the signature of a functional option that can be used
// to modify the NonceGen function.
type NonceGenOption func(opts *nonceGenCfg)

// nonceGenCfg holds all the optional NonceGen inputs.
type nonceGenCfg struct {
	sk       *schnorr.PrivateKey
	aggPk    *schnorr.PublicKey
	m        []byte
	extraIn  []byte
	randByte *[32]byte
}

// defaultNonceGenCfg constructs an empty nonceGenCfg.
func defaultNonceGenCfg() *nonceGenCfg {
	return &nonceGenCfg{}
}

// WithOptionSecretKey sets the optional secret key parameter (sk) of the
// NonceGen algo.
func WithOptionSecretKey(sk *schnorr.PrivateKey) NonceGenOption {
	return func(opts *nonceGenCfg) {
		opts.sk = sk
	}
}

// WithOptionAggKey sets the optional aggregated x-only pub key (aggpk) of the
// NonceGen algo.
func WithOptionAggKey(aggKey *schnorr.PublicKey) NonceGenOption {
	return func(opts *nonceGenCfg) {
		opts.aggPk = aggKey
	}
}

// WithOptionMessage sets the optional msg param of the NonceGen algo.
func WithOptionMessage(m []byte) NonceGenOption {
	return func(opts *nonceGenCfg) {
		opts.m = m
	}
}

// WithOptionExtraIn sets the optional auxiliary input (extra_in) of the
// NonceGen algo.
func WithOptionExtraIn(aux []byte) NonceGenOption {
	return func(opts *nonceGenCfg) {
		opts.extraIn = aux
	}
}

// WithRandBytes optionally sets the rand param of the NonceGen func. If this
// value is not manually set, then the crypt/rand package will be used to
// draw this value.
func WithRandBytes(rand [32]byte) NonceGenOption {
	return func(opts *nonceGenCfg) {
		opts.randByte = &rand
	}
}

// Nonce comprises a secnonce and a pubnonce.
type Nonce struct {
	*SecNonce
	*PubNonce
}

// SecNonce holds all the objects required to construct the `secnonce` part of
// a Nonce.
type SecNonce struct {
	k1, k2 *schnorr.PrivateKey
	pk     *schnorr.PublicKey
}

// GetPubNonce returns the corresponding public nonce of the SecNonce.
func (s *SecNonce) GetPubNonce() *PubNonce {
	return &PubNonce{
		R1: s.k1.PubKey,
		R2: s.k2.PubKey,
	}
}

// Bytes returns the serialised SecNonce.
//
//	k1 || k2 || pk
func (s *SecNonce) Bytes() []byte {
	res := make([]byte, SecNonceLen)

	k1Bytes := s.k1.Bytes()
	copy(res[:32], k1Bytes[:])

	k2Bytes := s.k2.Bytes()
	copy(res[32:64], k2Bytes[:])
	copy(res[64:], s.pk.PlainBytes())

	return res
}

// ParseSecNonce constructs a SecNonce from the given byte slice.
func ParseSecNonce(b []byte) (*SecNonce, error) {
	if len(b) != SecNonceLen {
		return nil, fmt.Errorf("invalid sec nonce len")
	}

	k1, err := schnorr.ParsePrivKeyBytes(b[:32])
	if err != nil {
		return nil, err
	}

	k2, err := schnorr.ParsePrivKeyBytes(b[32:64])
	if err != nil {
		return nil, err
	}

	pk, err := schnorr.ParsePlainPubKey(b[64:])
	if err != nil {
		return nil, err
	}

	return &SecNonce{
		k1: k1,
		k2: k2,
		pk: pk,
	}, nil
}

// PubNonce consists of the two Public nonces that make up the PubNonce.
//
//	R = R1 + b*R2
type PubNonce struct {
	R1, R2 *schnorr.PublicKey
}

// ParsePubNonce constructs a PubNonce from the given byte slice.
func ParsePubNonce(b []byte) (*PubNonce, error) {
	if len(b) != PubNonceLen {
		return nil, fmt.Errorf("bad pub nonce len")
	}

	n1Bytes := b[:33]
	n2Bytes := b[33:]

	R1 := schnorr.NewInfinityPubKey()
	R2 := schnorr.NewInfinityPubKey()

	var err error
	if !bytes.Equal(n1Bytes, zeroByteVector) {
		R1, err = schnorr.ParsePlainPubKey(n1Bytes)
		if err != nil {
			return nil, err
		}
	}

	if !bytes.Equal(n2Bytes, zeroByteVector) {
		R2, err = schnorr.ParsePlainPubKey(n2Bytes)
		if err != nil {
			return nil, err
		}
	}

	return &PubNonce{
		R1: R1,
		R2: R2,
	}, nil
}

// Bytes serialises the given PubNonce.
//   cbytes(p.R1) || cbytes(p.R2)
func (p *PubNonce) Bytes() []byte {
	res := make([]byte, PubNonceLen)

	if p.R1.IsInfinity {
		copy(res[:33], zeroByteVector)
	} else {
		copy(res[:33], p.R1.PlainBytes())
	}

	if p.R2.IsInfinity {
		copy(res[33:], zeroByteVector)
	} else {
		copy(res[33:], p.R2.PlainBytes())
	}

	return res
}

// NonceGen generates a Nonce from the given set of inputs.
func NonceGen(pk *schnorr.PublicKey, opts ...NonceGenOption) (*Nonce, error) {
	if pk == nil {
		return nil, fmt.Errorf("a public key must be specified")
	}

	cfg := defaultNonceGenCfg()
	for _, o := range opts {
		o(cfg)
	}

	if len(cfg.extraIn) > math.MaxUint32 {
		return nil, fmt.Errorf("extra input too long")
	}

	// Let rand' be a 32-byte array freshly drawn uniformly at random.
	var randBytes [32]byte
	if cfg.randByte == nil {
		if _, err := rand.Read(randBytes[:]); err != nil {
			return nil, err
		}
	} else {
		randBytes = *cfg.randByte
	}

	// If the optional argument sk is present:
	if cfg.sk != nil {
		// Let rand be the byte-wise xor of sk and hashMuSig/aux(rand')
		randBytes = schnorr.Xor(
			cfg.sk.Bytes(),
			schnorr.TaggedHash(AuxTag, randBytes[:]),
		)
	}

	var aggPk []byte
	if cfg.aggPk != nil {
		aggPk = cfg.aggPk.XOnlyBytes()
	}

	var mPrefixed []byte
	if cfg.m == nil {
		mPrefixed = []byte{0x00}
	} else {
		mPrefixed = make([]byte, 1+8+len(cfg.m))
		copy(mPrefixed[:1], []byte{0x01})
		binary.BigEndian.PutUint64(mPrefixed[1:9], uint64(len(cfg.m)))
		copy(mPrefixed[9:], cfg.m)
	}

	var aux []byte
	if cfg.extraIn != nil {
		aux = cfg.extraIn
	}

	k1, err := makeNonce(1, pk, randBytes[:], aggPk, mPrefixed, aux)
	if err != nil {
		return nil, err
	}

	k2, err := makeNonce(2, pk, randBytes[:], aggPk, mPrefixed, aux)
	if err != nil {
		return nil, err
	}

	secNonce := SecNonce{
		k1: k1,
		k2: k2,
		pk: pk,
	}

	return &Nonce{
		SecNonce: &secNonce,
		PubNonce: secNonce.GetPubNonce(),
	}, nil
}

func makeNonce(i uint8, pk *schnorr.PublicKey, rand, aggPk, mPrefixed,
	extraIn []byte) (*schnorr.PrivateKey, error) {

	extraInLen := make([]byte, 4)
	binary.BigEndian.PutUint32(extraInLen, uint32(len(extraIn)))

	hash := schnorr.TaggedHash(
		NonceTag,
		rand,
		[]byte{0x21}, pk.PlainBytes(),
		[]byte{byte(len(aggPk))}, aggPk,
		mPrefixed,
		extraInLen, extraIn,
		[]byte{i - 1},
	)

	return schnorr.PrivateKeyFromInt(schnorr.IntFromBytes(hash))
}

// NonceAgg aggregates the given set of PubNonces into a single PubNonce.
func NonceAgg(pNonces []*PubNonce) *PubNonce {
	nonces := []*schnorr.PublicKey{
		schnorr.NewInfinityPubKey(), schnorr.NewInfinityPubKey(),
	}

	for j, _ := range nonces {
		for _, pn := range pNonces {
			nn := pn.R1
			if j == 1 {
				nn = pn.R2
			}

			nonces[j] = nonces[j].Add(nn)
		}
	}

	return &PubNonce{
		R1: nonces[0],
		R2: nonces[1],
	}
}
