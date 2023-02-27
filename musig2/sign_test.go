package musig2

import (
	"bytes"
	"github.com/ellemouton/schnorr"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSign(t *testing.T) {
	skStr := "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671"

	pubkeys := []string{
		"03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
		"02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		"02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661",
		"020000000000000000000000000000000000000000000000000000000000000007",
	}
	secnonces := []string{
		"508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
		"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
	}

	pnonces := []string{
		"0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
		"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
		"032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046",
		"0237C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0387BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
		"0200000000000000000000000000000000000000000000000000000000000000090287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
	}

	aggnonces := []string{
		"028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
		"028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009",
		"028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
	}

	msgs := []string{
		"F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF",
		"",
		"2626262626262626262626262626262626262626262626262626262626262626262626262626",
	}

	tests := []struct {
		keyIndices    []int
		nonceIndices  []int
		aggNonceInxex int
		msgIndex      int
		signerIndex   int
		expectedSig   string
		expectErr     bool
	}{
		{
			keyIndices:    []int{0, 1, 2},
			nonceIndices:  []int{0, 1, 2},
			aggNonceInxex: 0,
			msgIndex:      0,
			signerIndex:   0,
			expectedSig:   "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB",
		},
		{
			keyIndices:    []int{1, 0, 2},
			nonceIndices:  []int{1, 0, 2},
			aggNonceInxex: 0,
			msgIndex:      0,
			signerIndex:   1,
			expectedSig:   "9FF2F7AAA856150CC8819254218D3ADEEB0535269051897724F9DB3789513A52",
		},
		{
			keyIndices:    []int{1, 2, 0},
			nonceIndices:  []int{1, 2, 0},
			aggNonceInxex: 0,
			msgIndex:      0,
			signerIndex:   2,
			expectedSig:   "FA23C359F6FAC4E7796BB93BC9F0532A95468C539BA20FF86D7C76ED92227900",
		},
		{
			keyIndices:    []int{0, 1},
			nonceIndices:  []int{0, 3},
			aggNonceInxex: 1,
			msgIndex:      0,
			signerIndex:   0,
			expectedSig:   "AE386064B26105404798F75DE2EB9AF5EDA5387B064B83D049CB7C5E08879531",
		},
		{
			keyIndices:    []int{0, 1, 2},
			nonceIndices:  []int{0, 1, 2},
			aggNonceInxex: 0,
			msgIndex:      1,
			signerIndex:   0,
			expectedSig:   "D7D63FFD644CCDA4E62BC2BC0B1D02DD32A1DC3030E155195810231D1037D82D",
		},
		{
			keyIndices:    []int{0, 1, 2},
			nonceIndices:  []int{0, 1, 2},
			aggNonceInxex: 0,
			msgIndex:      2,
			signerIndex:   0,
			expectedSig:   "E184351828DA5094A97C79CABDAAA0BFB87608C32E8829A4DF5340A6F243B78C",
		},
		{
			keyIndices:    []int{1, 2},
			aggNonceInxex: 0,
			msgIndex:      0,
			signerIndex:   0,
			expectErr:     true,
		},
		{
			keyIndices:    []int{1, 0, 3},
			aggNonceInxex: 0,
			msgIndex:      0,
			signerIndex:   0,
			expectErr:     true,
		},
		{
			keyIndices:    []int{1, 2, 0},
			aggNonceInxex: 2,
			msgIndex:      0,
			signerIndex:   0,
			expectErr:     true,
		},
		{
			keyIndices:    []int{1, 0, 3},
			aggNonceInxex: 3,
			msgIndex:      0,
			signerIndex:   0,
			expectErr:     true,
		},
		{
			keyIndices:    []int{1, 0, 3},
			aggNonceInxex: 4,
			msgIndex:      0,
			signerIndex:   0,
			expectErr:     true,
		},
	}

	sk, err := schnorr.ParsePrivKeyBytes(parseHexStr(t, skStr))
	require.NoError(t, err)

	secNonce, err := ParseSecNonce(parseHexStr(t, secnonces[0]))
	require.NoError(t, err)

	for _, test := range tests {
		t.Run("", func(t *testing.T) {

			pks := make([]*schnorr.PublicKey, len(test.keyIndices))
			for i, k := range test.keyIndices {
				pks[i], err = schnorr.ParsePlainPubKey(
					parseHexStr(t, pubkeys[k]),
				)
				if err != nil && test.expectErr {
					return
				}
				require.NoError(t, err)
			}

			pns := make([]*PubNonce, len(test.nonceIndices))
			for i, k := range test.nonceIndices {
				pns[i], err = ParsePubNonce(
					parseHexStr(t, pnonces[k]),
				)
				if err != nil && test.expectErr {
					return
				}
				require.NoError(t, err)
			}
			aggNonce1 := NonceAgg(pns)

			aggNonce, err := ParsePubNonce(
				parseHexStr(t, aggnonces[test.aggNonceInxex]),
			)
			if err != nil && test.expectErr {
				return
			}
			require.NoError(t, err)

			aggNoncesEqual := bytes.Equal(
				aggNonce1.Bytes(), aggNonce.Bytes(),
			)
			if !aggNoncesEqual && test.expectErr {
				return
			}

			msg := parseHexStr(t, msgs[test.msgIndex])

			sctx := &SessionContext{
				AggPubNonce: aggNonce,
				PubKeys:     pks,
				Msg:         msg,
			}

			ps, err := Sign(secNonce, sk, sctx)
			require.NoError(t, err)

			expectedSig := parseHexStr(t, test.expectedSig)
			require.True(t, bytes.Equal(expectedSig, ps[:]))
		})
	}
}
