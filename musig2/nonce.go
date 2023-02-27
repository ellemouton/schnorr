package musig2

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/ellemouton/schnorr"
	"math"
)

const (
	AuxTag   = "MuSig/aux"
	NonceTag = "MuSig/nonce"
)

type NonceGenOption func(opts *nonceGenCfg)

type nonceGenCfg struct {
	sk       *schnorr.PrivateKey
	aggPk    *schnorr.PublicKey
	m        []byte
	extraIn  []byte
	randByte *[32]byte
}

func defaultNonceGenCfg() *nonceGenCfg {
	return &nonceGenCfg{}
}

func WithOptionSecretKey(sk *schnorr.PrivateKey) NonceGenOption {
	return func(opts *nonceGenCfg) {
		opts.sk = sk
	}
}

func WithOptionAggKey(aggKey *schnorr.PublicKey) NonceGenOption {
	return func(opts *nonceGenCfg) {
		opts.aggPk = aggKey
	}
}

func WithOptionMessage(m []byte) NonceGenOption {
	return func(opts *nonceGenCfg) {
		opts.m = m
	}
}

func WithOptionExtraIn(aux []byte) NonceGenOption {
	return func(opts *nonceGenCfg) {
		opts.extraIn = aux
	}
}

func WithRandBytes(rand [32]byte) NonceGenOption {
	return func(opts *nonceGenCfg) {
		opts.randByte = &rand
	}
}

type Nonce struct {
	*SecNonce
	*PubNonce
}

type SecNonce struct {
	k1, k2 *schnorr.PrivateKey
	pk     *schnorr.PublicKey
}

func (s *SecNonce) GetPubNonce() *PubNonce {
	return &PubNonce{
		R1: s.k1.PubKey,
		R2: s.k2.PubKey,
	}
}

func (s *SecNonce) Bytes() []byte {
	res := make([]byte, 32+32+33)

	k1Bytes := s.k1.Bytes()
	copy(res[:32], k1Bytes[:])

	k2Bytes := s.k2.Bytes()
	copy(res[32:64], k2Bytes[:])
	copy(res[64:], s.pk.PlainBytes())

	return res
}

type PubNonce struct {
	R1, R2 *schnorr.PublicKey
}

func (p *PubNonce) Bytes() []byte {
	res := make([]byte, 66)
	copy(res[:33], p.R1.PlainBytes())
	copy(res[33:], p.R2.PlainBytes())

	return res
}

func NonceGen(pk *schnorr.PublicKey, opts ...NonceGenOption) (*Nonce, error) {
	cfg := defaultNonceGenCfg()
	for _, o := range opts {
		o(cfg)
	}

	if len(cfg.extraIn) > math.MaxUint32 {
		return nil, fmt.Errorf("extra input too long")
	}

	if pk == nil {
		return nil, fmt.Errorf("a public key must be specified")
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

// Let ki = int(hashMuSig/nonce(rand || bytes(1, len(pk)) || pk || bytes(1, len(aggpk)) || aggpk || m_prefixed || bytes(4, len(extra_in)) || extra_in || bytes(1, i - 1))) mod n for i = 1,2
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

	ii := schnorr.IntFromBytes(hash)

	return schnorr.PrivateKeyFromInt(ii)
}
