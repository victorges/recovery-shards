package command

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/victorges/recovery-shards/model"
)

func TestRecoverErrors(t *testing.T) {
	// Create an invalid share
	invalidShare := model.MnemonicShare{
		Identifier: []byte{0x01},
		Mnemonic:   "invalid mnemonic phrase",
	}

	testCases := []struct {
		name             string
		shares           []model.MnemonicShare
		expectedMnemonic string
		errMsg           string
	}{
		{
			name: "insufficient_shares",
			shares: []model.MnemonicShare{
				mustMnemonicShare("0x0110", "goose apple ecology ill reduce poem wish olive guitar health run chimney limb village nice dismiss razor meat property try talent toward clever cherry"),
			},
			errMsg: "less than two parts cannot be used to reconstruct the secret",
		},
		{
			name: "invalid_share",
			shares: append(
				[]model.MnemonicShare{mustMnemonicShare("0x0110", "goose apple ecology ill reduce poem wish olive guitar health run chimney limb village nice dismiss razor meat property try talent toward clever cherry")},
				invalidShare,
			),
			errMsg: "invalid mnemonic",
		},
		{
			name: "valid_shares_2_for_3",
			shares: []model.MnemonicShare{
				mustMnemonicShare("0xade1", "drum wage genuine tourist slim hungry fragile lava shop apple large off cheap hover trial phrase bag cost sell person salt amount cute lottery"),
				mustMnemonicShare("0xf606", "ride magnet elbow uniform slight fat unlock attitude calm blouse pretty axis health dentist shaft gorilla exist fossil hunt chaos frame panther ankle please"),
			},
			expectedMnemonic: "goose apple ecology ill reduce poem wish olive guitar health run chimney limb village nice dismiss razor meat property try talent toward clever cherry",
		},
		{
			name: "valid_shares_3_for_5",
			shares: []model.MnemonicShare{
				mustMnemonicShare("0x5954", "ankle salad deposit junior arrest raw box place cradle brand force boat weird involve claw neck paper vast riot prize embrace rough pelican eight"),
				mustMnemonicShare("0x9b9f", "aerobic boat baby injury animal frequent artwork happy autumn foam rebuild segment rude fringe mix calm kite patrol garbage model material federal brass hazard"),
				mustMnemonicShare("0xf78d", "slam border talk switch suspect wear deal core undo cement impact route hollow pelican peasant give hour ski huge raccoon elite arrest theme rare"),
			},
			expectedMnemonic: "border area early digital pen menu defy surround dove brand tongue dad eternal jazz position kid fatigue pelican cradle wood fortune outer loyal current",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mnemonic, err := Recover(tc.shares)
			if tc.errMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedMnemonic, mnemonic)
			}
		})
	}
}

func mustMnemonicShare(identifier string, mnemonic string) model.MnemonicShare {
	share, err := model.NewMnemonicShare(identifier, mnemonic)
	if err != nil {
		panic(err)
	}
	return share
}
