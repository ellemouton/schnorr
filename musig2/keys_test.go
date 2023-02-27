package musig2

import (
	"github.com/ellemouton/schnorr"
	"github.com/stretchr/testify/require"
	"testing"
)

// TestKeySort asserts that the KeySort function passes the test vector defined
// at https://github.com/jonasnick/bips/blob/musig2/bip-musig2/vectors/key_sort_vectors.json
func TestKeySort(t *testing.T) {
	inputStrs := []string{
		"02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
		"02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		"03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
		"023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
		"02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EFF",
		"02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
	}

	expectedOutStrs := []string{
		"023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
		"02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
		"02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
		"02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EFF",
		"02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		"03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
	}

	inputs := convertStrsToPubKeys(t, inputStrs)
	expectedOut := convertStrsToPubKeys(t, expectedOutStrs)

	outputs := KeySort(inputs)
	require.Len(t, outputs, len(expectedOut))

	for i, p := range outputs {
		require.True(t, p.Equal(expectedOut[i]))
	}
}

func convertStrsToPubKeys(t *testing.T, strs []string) []*schnorr.PublicKey {
	res := make([]*schnorr.PublicKey, len(strs))
	for i, s := range strs {
		pub, err := schnorr.ParsePlainPubKeyHexString(s)
		require.NoError(t, err)

		res[i] = pub
	}

	return res
}
