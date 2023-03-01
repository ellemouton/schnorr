package musig2

import (
	"bytes"
	"encoding/hex"
	"fmt"
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

	tweaks := []string{
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
		"252E4BD67410A76CDF933D30EAA1608214037F1B105A013ECCD3C5C184A6110B",
	}

	tests := []struct {
		keyIndices   []int
		tweakIndices []int
		isXOnlyT     bool
		expectErr    bool
		expectedAgg  string
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
		{
			keyIndices:   []int{0, 1},
			tweakIndices: []int{0},
			isXOnlyT:     true,
			expectErr:    true,
		},
		{
			keyIndices:   []int{6},
			tweakIndices: []int{1},
			isXOnlyT:     false,
			expectErr:    true,
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

			inputTweakStrs := make([]string, len(test.tweakIndices))
			for i, index := range test.tweakIndices {
				inputTweakStrs[i] = tweaks[index]
			}

			ts := make([][]byte, len(inputTweakStrs))
			for i, s := range inputTweakStrs {

				tweak, err := hex.DecodeString(s)
				require.NoError(t, err)

				ts[i] = tweak
			}

			aggKeyCtx, err := KeyAgg(inputs)
			if err != nil && test.expectErr {
				return
			}
			require.NoError(t, err)

			if len(ts) != 0 {
				tweak, err := NewTweak(ts[0], test.isXOnlyT)
				if err != nil && test.expectErr {
					return
				}

				err = aggKeyCtx.ApplyTweak(tweak)
				if err != nil && test.expectErr {
					return
				}
				require.NoError(t, err)
			}

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

func TestApplyTweak(t *testing.T) {
	sk := "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671"
	pubkeys := []string{
		"03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
		"02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		"02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
	}
	secnonce := "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
	pnonces := []string{
		"0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
		"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
		"032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046",
	}
	aggnonce := "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9"
	tweaks := []string{
		"E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB",
		"AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455",
		"F52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0",
		"1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D",
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
	}
	msg := "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF"

	tests := []struct {
		keyIndices   []int
		nonceIndices []int
		tweakIndices []int
		tweakModes   []bool
		expected     string
	}{
		{
			keyIndices:   []int{1, 2, 0},
			nonceIndices: []int{1, 2, 0},
			tweakIndices: []int{0},
			tweakModes:   []bool{true},
			expected:     "E28A5C66E61E178C2BA19DB77B6CF9F7E2F0F56C17918CD13135E60CC848FE91",
		},
		{
			keyIndices:   []int{1, 2, 0},
			nonceIndices: []int{1, 2, 0},
			tweakIndices: []int{0},
			tweakModes:   []bool{false},
			expected:     "38B0767798252F21BF5702C48028B095428320F73A4B14DB1E25DE58543D2D2D",
		},
		{
			keyIndices:   []int{1, 2, 0},
			nonceIndices: []int{1, 2, 0},
			tweakIndices: []int{0, 1},
			tweakModes:   []bool{false, true},
			expected:     "408A0A21C4A0F5DACAF9646AD6EB6FECD7F7A11F03ED1F48DFFF2185BC2C2408",
		},
		{
			keyIndices:   []int{1, 2, 0},
			nonceIndices: []int{1, 2, 0},
			tweakIndices: []int{0, 1, 2, 3},
			tweakModes:   []bool{false, false, true, true},
			expected:     "45ABD206E61E3DF2EC9E264A6FEC8292141A633C28586388235541F9ADE75435",
		},
		{
			keyIndices:   []int{1, 2, 0},
			nonceIndices: []int{1, 2, 0},
			tweakIndices: []int{0, 1, 2, 3},
			tweakModes:   []bool{true, false, true, false},
			expected:     "B255FDCAC27B40C7CE7848E2D3B7BF5EA0ED756DA81565AC804CCCA3E1D5D239",
		},
	}

	aggNonce, err := ParsePubNonce(parseHexStr(t, aggnonce))
	require.NoError(t, err)

	secNonce, err := ParseSecNonce(parseHexStr(t, secnonce))
	require.NoError(t, err)

	secKey, err := schnorr.ParsePrivKeyBytes(parseHexStr(t, sk))
	require.NoError(t, err)

	msgBytes := parseHexStr(t, msg)

	for i, test := range tests {
		test := test
		name := fmt.Sprintf("%d", i)

		t.Run(name, func(t *testing.T) {
			pns := make([]*PubNonce, len(test.nonceIndices))
			for i, k := range test.nonceIndices {
				pns[i], err = ParsePubNonce(
					parseHexStr(t, pnonces[k]),
				)
				require.NoError(t, err)
			}

			aggNonce1 := NonceAgg(pns)
			require.True(t, bytes.Equal(aggNonce1.Bytes(), aggNonce.Bytes()))

			pks := make([]*schnorr.PublicKey, len(test.keyIndices))
			for i, k := range test.keyIndices {
				pks[i], err = schnorr.ParsePlainPubKey(
					parseHexStr(t, pubkeys[k]),
				)
				require.NoError(t, err)
			}

			tweakList := make([]*Tweak, len(test.tweakIndices))
			for i, k := range test.tweakIndices {
				tweakList[i], err = NewTweak(
					parseHexStr(t, tweaks[k]),
					test.tweakModes[k],
				)
				require.NoError(t, err)
			}

			ctx := NewSessionContext(
				aggNonce, pks, msgBytes, tweakList,
			)

			partialSig, err := Sign(ctx, secNonce, secKey)
			require.NoError(t, err)

			expectedSig := parseHexStr(t, test.expected)
			require.True(t, bytes.Equal(partialSig.Bytes(), expectedSig))
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
