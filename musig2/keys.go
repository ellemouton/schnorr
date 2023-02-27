package musig2

import (
	"bytes"
	"github.com/ellemouton/schnorr"
	"sort"
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
