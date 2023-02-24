package schnorr

import "crypto/sha256"

const TaggedHashSize = 32

// TaggedHash implements the tagged hash scheme described in BIP-340.
func TaggedHash(tag string, data ...[]byte) [TaggedHashSize]byte {
	shaTag := sha256.Sum256([]byte(tag))

	// h = sha256(sha256(tag) || sha256(tag) || msg)
	h := sha256.New()
	h.Write(shaTag[:])
	h.Write(shaTag[:])

	for _, msg := range data {
		h.Write(msg)
	}

	taggedHash := h.Sum(nil)

	var th [TaggedHashSize]byte
	copy(th[:], taggedHash)

	return th
}
