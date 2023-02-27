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

func TestKeyAgg(t *testing.T) {
	pubkeys := []string{
		"02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		"03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
		"023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
		"020000000000000000000000000000000000000000000000000000000000000005",
		"02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
		"04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		"03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
	}

	tests := []struct {
		keyIndices  []int
		expectErr   bool
		expectedAgg string
	}{
		{
			keyIndices:  []int{0, 1, 2},
			expectedAgg: "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C",
		},
		{
			keyIndices:  []int{2, 1, 0},
			expectedAgg: "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B",
		},
		{
			keyIndices:  []int{0, 0, 0},
			expectedAgg: "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935",
		},
		{
			keyIndices:  []int{0, 0, 1, 1},
			expectedAgg: "69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E",
		},
		{
			keyIndices: []int{0, 3},
			expectErr:  true,
		},
		{
			keyIndices: []int{0, 4},
			expectErr:  true,
		},
		{
			keyIndices: []int{0, 5},
			expectErr:  true,
		},
	}

	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			inputKeyStrs := make([]string, len(test.keyIndices))
			for i, index := range test.keyIndices {
				inputKeyStrs[i] = pubkeys[index]
			}

			inputs := make([]*schnorr.PublicKey, len(inputKeyStrs))
			for i, s := range inputKeyStrs {
				pub, err := schnorr.ParsePlainPubKeyHexString(s)
				if err != nil && test.expectErr {
					return
				}
				require.NoError(t, err)

				inputs[i] = pub
			}

			aggKeyCtx, err := KeyAgg(inputs)
			if err != nil && test.expectErr {
				return
			}
			require.NoError(t, err)

			expectedAgg, err := schnorr.ParseXOnlyPubKeyHexString(
				test.expectedAgg,
			)
			if err != nil && test.expectErr {
				return
			}
			require.NoError(t, err)

			require.True(t, aggKeyCtx.Q.Equal(expectedAgg))
		})
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
