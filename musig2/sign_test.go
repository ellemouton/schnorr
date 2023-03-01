package musig2

import (
	"bytes"
	"fmt"
	"github.com/ellemouton/schnorr"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	skStr = "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671"

	pubkeys = []string{
		"03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
		"02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
		"02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661",
		"020000000000000000000000000000000000000000000000000000000000000007",
	}
	secnonces = []string{
		"508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
		"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
	}

	pnonces = []string{
		"0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
		"0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
		"032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046",
		"0237C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0387BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
		"0200000000000000000000000000000000000000000000000000000000000000090287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
	}

	aggnonces = []string{
		"028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
		"028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009",
		"028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
	}

	msgs = []string{
		"F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF",
		"",
		"2626262626262626262626262626262626262626262626262626262626262626262626262626",
	}
)

func TestSign(t *testing.T) {
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

	for i, test := range tests {
		test := test
		name := fmt.Sprintf("%d", i)
		t.Run(name, func(t *testing.T) {
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

			sctx := NewSessionContext(aggNonce, pks, msg, nil)

			ps, err := Sign(sctx, secNonce, sk)
			require.NoError(t, err)

			expectedSig := parseHexStr(t, test.expectedSig)
			require.True(t, bytes.Equal(expectedSig, ps.Bytes()))
		})
	}
}

func TestVerifyPartialSig(t *testing.T) {
	tests := []struct {
		sig          string
		keyIndices   []int
		nonceIndices []int
		msgIndex     int
		signerIndex  int
	}{
		{
			sig:          "97AC833ADCB1AFA42EBF9E0725616F3C9A0D5B614F6FE283CEAAA37A8FFAF406",
			keyIndices:   []int{0, 1, 2},
			nonceIndices: []int{0, 1, 2},
			msgIndex:     0,
			signerIndex:  0,
		},
		{
			sig:          "68537CC5234E505BD14061F8DA9E90C220A181855FD8BDB7F127BB12403B4D3B",
			keyIndices:   []int{0, 1, 2},
			nonceIndices: []int{0, 1, 2},
			msgIndex:     0,
			signerIndex:  0,
		},
		{
			sig:          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
			keyIndices:   []int{0, 1, 2},
			nonceIndices: []int{0, 1, 2},
			msgIndex:     0,
			signerIndex:  0,
		},
	}

	for i, test := range tests {
		name := fmt.Sprintf("%d", i)
		test := test
		t.Run(name, func(t *testing.T) {
			sig := parseHexStr(t, test.sig)

			var err error
			pks := make([]*schnorr.PublicKey, len(test.keyIndices))
			for i, k := range test.keyIndices {
				pks[i], err = schnorr.ParsePlainPubKey(
					parseHexStr(t, pubkeys[k]),
				)
				require.NoError(t, err)
			}

			pns := make([]*PubNonce, len(test.nonceIndices))
			for i, k := range test.nonceIndices {
				pns[i], err = ParsePubNonce(
					parseHexStr(t, pnonces[k]),
				)
				require.NoError(t, err)
			}

			msg := parseHexStr(t, msgs[test.msgIndex])

			psig, err := ParsePartialSig(sig)
			if err != nil {
				return
			}

			err = psig.Verify(
				pns, pks, nil, msg, test.signerIndex,
			)
			require.Error(t, err)
		})
	}
}

func TestPartialSigAgg(t *testing.T) {
	pubkeys := []string{
		"03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
		"02D2DC6F5DF7C56ACF38C7FA0AE7A759AE30E19B37359DFDE015872324C7EF6E05",
		"03C7FB101D97FF930ACD0C6760852EF64E69083DE0B06AC6335724754BB4B0522C",
		"02352433B21E7E05D3B452B81CAE566E06D2E003ECE16D1074AABA4289E0E3D581",
	}

	pnonces := []string{
		"036E5EE6E28824029FEA3E8A9DDD2C8483F5AF98F7177C3AF3CB6F47CAF8D94AE902DBA67E4A1F3680826172DA15AFB1A8CA85C7C5CC88900905C8DC8C328511B53E",
		"03E4F798DA48A76EEC1C9CC5AB7A880FFBA201A5F064E627EC9CB0031D1D58FC5103E06180315C5A522B7EC7C08B69DCD721C313C940819296D0A7AB8E8795AC1F00",
		"02C0068FD25523A31578B8077F24F78F5BD5F2422AFF47C1FADA0F36B3CEB6C7D202098A55D1736AA5FCC21CF0729CCE852575C06C081125144763C2C4C4A05C09B6",
		"031F5C87DCFBFCF330DEE4311D85E8F1DEA01D87A6F1C14CDFC7E4F1D8C441CFA40277BF176E9F747C34F81B0D9F072B1B404A86F402C2D86CF9EA9E9C69876EA3B9",
		"023F7042046E0397822C4144A17F8B63D78748696A46C3B9F0A901D296EC3406C302022B0B464292CF9751D699F10980AC764E6F671EFCA15069BBE62B0D1C62522A",
		"02D97DDA5988461DF58C5897444F116A7C74E5711BF77A9446E27806563F3B6C47020CBAD9C363A7737F99FA06B6BE093CEAFF5397316C5AC46915C43767AE867C00",
	}

	tweaks := []string{
		"B511DA492182A91B0FFB9A98020D55F260AE86D7ECBD0399C7383D59A5F2AF7C",
		"A815FE049EE3C5AAB66310477FBC8BCCCAC2F3395F59F921C364ACD78A2F48DC",
		"75448A87274B056468B977BE06EB1E9F657577B7320B0A3376EA51FD420D18A8",
	}

	psigs := []string{
		"B15D2CD3C3D22B04DAE438CE653F6B4ECF042F42CFDED7C41B64AAF9B4AF53FB",
		"6193D6AC61B354E9105BBDC8937A3454A6D705B6D57322A5A472A02CE99FCB64",
		"9A87D3B79EC67228CB97878B76049B15DBD05B8158D17B5B9114D3C226887505",
		"66F82EA90923689B855D36C6B7E032FB9970301481B99E01CDB4D6AC7C347A15",
		"4F5AEE41510848A6447DCD1BBC78457EF69024944C87F40250D3EF2C25D33EFE",
		"DDEF427BBB847CC027BEFF4EDB01038148917832253EBC355FC33F4A8E2FCCE4",
		"97B890A26C981DA8102D3BC294159D171D72810FDF7C6A691DEF02F0F7AF3FDC",
		"53FA9E08BA5243CBCB0D797C5EE83BC6728E539EB76C2D0BF0F971EE4E909971",
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
	}

	msg := "599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869"

	tests := []struct {
		aggnonce     string
		nonceIndices []int
		keyIndices   []int
		tweakIndices []int
		tweakModes   []bool
		psigIndices  []int
		expected     string
	}{
		{
			aggnonce:     "0341432722C5CD0268D829C702CF0D1CBCE57033EED201FD335191385227C3210C03D377F2D258B64AADC0E16F26462323D701D286046A2EA93365656AFD9875982B",
			nonceIndices: []int{0, 1},
			keyIndices:   []int{0, 1},
			psigIndices:  []int{0, 1},
			expected:     "041DA22223CE65C92C9A0D6C2CAC828AAF1EEE56304FEC371DDF91EBB2B9EF0912F1038025857FEDEB3FF696F8B99FA4BB2C5812F6095A2E0004EC99CE18DE1E",
		},
		{
			aggnonce:     "0224AFD36C902084058B51B5D36676BBA4DC97C775873768E58822F87FE437D792028CB15929099EEE2F5DAE404CD39357591BA32E9AF4E162B8D3E7CB5EFE31CB20",
			nonceIndices: []int{0, 2},
			keyIndices:   []int{0, 2},
			psigIndices:  []int{2, 3},
			expected:     "1069B67EC3D2F3C7C08291ACCB17A9C9B8F2819A52EB5DF8726E17E7D6B52E9F01800260A7E9DAC450F4BE522DE4CE12BA91AEAF2B4279219EF74BE1D286ADD9",
		},
		{
			aggnonce:     "0208C5C438C710F4F96A61E9FF3C37758814B8C3AE12BFEA0ED2C87FF6954FF186020B1816EA104B4FCA2D304D733E0E19CEAD51303FF6420BFD222335CAA402916D",
			nonceIndices: []int{0, 3},
			keyIndices:   []int{0, 2},
			tweakIndices: []int{0},
			tweakModes:   []bool{false},
			psigIndices:  []int{4, 5},
			expected:     "5C558E1DCADE86DA0B2F02626A512E30A22CF5255CAEA7EE32C38E9A71A0E9148BA6C0E6EC7683B64220F0298696F1B878CD47B107B81F7188812D593971E0CC",
		},
		{
			aggnonce:     "02B5AD07AFCD99B6D92CB433FBD2A28FDEB98EAE2EB09B6014EF0F8197CD58403302E8616910F9293CF692C49F351DB86B25E352901F0E237BAFDA11F1C1CEF29FFD",
			nonceIndices: []int{0, 4},
			keyIndices:   []int{0, 3},
			tweakIndices: []int{0, 1, 2},
			tweakModes:   []bool{true, false, true},
			psigIndices:  []int{6, 7},
			expected:     "839B08820B681DBA8DAF4CC7B104E8F2638F9388F8D7A555DC17B6E6971D7426CE07BF6AB01F1DB50E4E33719295F4094572B79868E440FB3DEFD3FAC1DB589E",
		},
	}

	for i, test := range tests {
		test := test
		name := fmt.Sprintf("%d", i)
		t.Run(name, func(t *testing.T) {
			aggNonce, err := ParsePubNonce(parseHexStr(t, test.aggnonce))
			require.NoError(t, err)

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

			partialSigs := make([]*PartialSig, len(test.psigIndices))
			for i, k := range test.psigIndices {
				partialSigs[i], err = ParsePartialSig(
					parseHexStr(t, psigs[k]),
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

			expectedSig := parseHexStr(t, test.expected)

			ctx := NewSessionContext(
				aggNonce, pks, parseHexStr(t, msg), tweakList,
			)

			aggSig, err := ctx.PartialSigAgg(partialSigs)
			require.NoError(t, err)

			aggSigBytes := aggSig.Bytes()
			require.True(t, bytes.Equal(aggSigBytes[:], expectedSig))
		})
	}
}
