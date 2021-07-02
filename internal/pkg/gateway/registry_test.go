/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gateway

import (
	"testing"

	"github.com/hyperledger/fabric-protos-go/common"

	"github.com/golang/protobuf/proto"
	dp "github.com/hyperledger/fabric-protos-go/discovery"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/common/policydsl"
	"github.com/stretchr/testify/require"
)

func TestFilteredLayouts(t *testing.T) {
	t.Run("SBE satisfied by one layout", func(t *testing.T) {
		// keyPolicy, err := policydsl.FromString("OutOf(1, 'Org1.member', 'Org2.member')")
		keyPolicy, err := policydsl.FromString("OutOf(1, 'Org2.member')")
		require.NoError(t, err)
		keyPolicies := []*common.SignaturePolicyEnvelope{keyPolicy}

		descriptor := &dp.EndorsementDescriptor{
			Chaincode: "mychaincode",
			EndorsersByGroups: map[string]*dp.Peers{
				"G1": {Peers: []*dp.Peer{mockPeer(t, "peer1", "Org1")}},
				"G2": {Peers: []*dp.Peer{mockPeer(t, "peer2", "Org2")}},
			},
			Layouts: []*dp.Layout{
				{QuantitiesByGroup: map[string]uint32{"G1": 1}},
				{QuantitiesByGroup: map[string]uint32{"G2": 1}},
			},
		}

		layout, err := filteredLayouts(descriptor, keyPolicies)
		require.NoError(t, err)

		expected := []*dp.Layout{
			{QuantitiesByGroup: map[string]uint32{"G2": 1}},
		}
		require.Equal(t, expected, layout)
	})

	t.Run("SBE satisfied by two layouts", func(t *testing.T) {
		keyPolicy, err := policydsl.FromString("OutOf(1, 'Org2.member')")
		require.NoError(t, err)
		keyPolicies := []*common.SignaturePolicyEnvelope{keyPolicy}

		descriptor := &dp.EndorsementDescriptor{
			Chaincode: "mychaincode",
			EndorsersByGroups: map[string]*dp.Peers{
				"G1": {Peers: []*dp.Peer{mockPeer(t, "peer1", "Org1")}},
				"G2": {Peers: []*dp.Peer{mockPeer(t, "peer2", "Org2")}},
				"G3": {Peers: []*dp.Peer{mockPeer(t, "peer3", "Org3")}},
			},
			Layouts: []*dp.Layout{ // 2 out of 3
				{QuantitiesByGroup: map[string]uint32{"G1": 1, "G2": 1}},
				{QuantitiesByGroup: map[string]uint32{"G1": 1, "G3": 1}},
				{QuantitiesByGroup: map[string]uint32{"G2": 1, "G3": 1}},
			},
		}

		layout, err := filteredLayouts(descriptor, keyPolicies)
		require.NoError(t, err)

		expected := []*dp.Layout{
			{QuantitiesByGroup: map[string]uint32{"G1": 1, "G2": 1}},
			{QuantitiesByGroup: map[string]uint32{"G2": 1, "G3": 1}},
		}
		require.Equal(t, expected, layout)
	})

	t.Run("SBE require two orgs, satisfied by one layouts", func(t *testing.T) {
		keyPolicy, err := policydsl.FromString("OutOf(2, 'Org2.member', 'Org1.member')")
		require.NoError(t, err)
		keyPolicies := []*common.SignaturePolicyEnvelope{keyPolicy}

		descriptor := &dp.EndorsementDescriptor{
			Chaincode: "mychaincode",
			EndorsersByGroups: map[string]*dp.Peers{
				"G1": {Peers: []*dp.Peer{mockPeer(t, "peer1", "Org1")}},
				"G2": {Peers: []*dp.Peer{mockPeer(t, "peer2", "Org2")}},
				"G3": {Peers: []*dp.Peer{mockPeer(t, "peer3", "Org3")}},
			},
			Layouts: []*dp.Layout{ // 2 out of 3
				{QuantitiesByGroup: map[string]uint32{"G1": 1, "G2": 1}},
				{QuantitiesByGroup: map[string]uint32{"G1": 1, "G3": 1}},
				{QuantitiesByGroup: map[string]uint32{"G2": 1, "G3": 1}},
			},
		}

		layout, err := filteredLayouts(descriptor, keyPolicies)
		require.NoError(t, err)

		expected := []*dp.Layout{
			{QuantitiesByGroup: map[string]uint32{"G1": 1, "G2": 1}},
		}
		require.Equal(t, expected, layout)
	})

	t.Run("Multiple SBE policies require two orgs, satisfied by one layout", func(t *testing.T) {
		keyPolicy1, err := policydsl.FromString("OutOf(1, 'Org1.member', 'Org2.member')")
		require.NoError(t, err)
		keyPolicy2, err := policydsl.FromString("OutOf(1, 'Org1.member', 'Org3.member')")
		require.NoError(t, err)
		keyPolicy3, err := policydsl.FromString("OutOf(2, 'Org2.member', 'Org3.member')")
		require.NoError(t, err)
		keyPolicies := []*common.SignaturePolicyEnvelope{keyPolicy1, keyPolicy2, keyPolicy3}

		descriptor := &dp.EndorsementDescriptor{
			Chaincode: "mychaincode",
			EndorsersByGroups: map[string]*dp.Peers{
				"G1": {Peers: []*dp.Peer{mockPeer(t, "peer1", "Org1")}},
				"G2": {Peers: []*dp.Peer{mockPeer(t, "peer2", "Org2")}},
				"G3": {Peers: []*dp.Peer{mockPeer(t, "peer3", "Org3")}},
			},
			Layouts: []*dp.Layout{ // 2 out of 3
				{QuantitiesByGroup: map[string]uint32{"G1": 1, "G2": 1}},
				{QuantitiesByGroup: map[string]uint32{"G1": 1, "G3": 1}},
				{QuantitiesByGroup: map[string]uint32{"G2": 1, "G3": 1}},
			},
		}

		layout, err := filteredLayouts(descriptor, keyPolicies)
		require.NoError(t, err)

		expected := []*dp.Layout{
			{QuantitiesByGroup: map[string]uint32{"G2": 1, "G3": 1}},
		}
		require.Equal(t, expected, layout)
	})

	t.Run("Multiple SBE policies require more orgs than can be satisfied by any discovery layouts", func(t *testing.T) {
		keyPolicy1, err := policydsl.FromString("OutOf(1, 'Org1.member')")
		require.NoError(t, err)
		keyPolicy2, err := policydsl.FromString("OutOf(1, 'Org1.member', 'Org3.member')")
		require.NoError(t, err)
		keyPolicy3, err := policydsl.FromString("OutOf(2, 'Org2.member', 'Org3.member')")
		require.NoError(t, err)
		keyPolicies := []*common.SignaturePolicyEnvelope{keyPolicy1, keyPolicy2, keyPolicy3}

		descriptor := &dp.EndorsementDescriptor{
			Chaincode: "mychaincode",
			EndorsersByGroups: map[string]*dp.Peers{
				"G1": {Peers: []*dp.Peer{mockPeer(t, "peer1", "Org1")}},
				"G2": {Peers: []*dp.Peer{mockPeer(t, "peer2", "Org2")}},
				"G3": {Peers: []*dp.Peer{mockPeer(t, "peer3", "Org3")}},
			},
			Layouts: []*dp.Layout{ // 2 out of 3
				{QuantitiesByGroup: map[string]uint32{"G1": 1, "G2": 1}},
				{QuantitiesByGroup: map[string]uint32{"G1": 1, "G3": 1}},
				{QuantitiesByGroup: map[string]uint32{"G2": 1, "G3": 1}},
			},
		}

		layout, err := filteredLayouts(descriptor, keyPolicies)
		require.NoError(t, err)

		expected := []*dp.Layout{
			{QuantitiesByGroup: map[string]uint32{"G1": 1, "G2": 1, "G3": 1}},
		}
		require.Equal(t, expected, layout)
	})
}

func TestMergeKeyPolicies(t *testing.T) {
	t.Run("Two identical policies", func(t *testing.T) {
		keyPolicy1, err := policydsl.FromString("OutOf(1, 'Org1.member')")
		require.NoError(t, err)
		keyPolicy2, err := policydsl.FromString("OutOf(1, 'Org1.member')")
		require.NoError(t, err)

		keyPolicies := []*common.SignaturePolicyEnvelope{keyPolicy1, keyPolicy2}

		cps, err := mergeKeyPolicies(keyPolicies)
		require.NoError(t, err)
		require.Len(t, cps, 1)
		require.Len(t, cps[0], 1)
	})

	t.Run("Two different policies", func(t *testing.T) {
		keyPolicy1, err := policydsl.FromString("OutOf(1, 'Org1.member')")
		require.NoError(t, err)
		keyPolicy2, err := policydsl.FromString("OutOf(1, 'Org2.member')")
		require.NoError(t, err)

		keyPolicies := []*common.SignaturePolicyEnvelope{keyPolicy1, keyPolicy2}

		cps, err := mergeKeyPolicies(keyPolicies)
		require.NoError(t, err)
		require.Len(t, cps, 1)
		require.Len(t, cps[0], 2)
	})

	t.Run("Three different policies - one possible arrangement", func(t *testing.T) {
		keyPolicy1, err := policydsl.FromString("OutOf(1, 'Org1.member')")
		require.NoError(t, err)
		keyPolicy2, err := policydsl.FromString("OutOf(1, 'Org2.member')")
		require.NoError(t, err)
		keyPolicy3, err := policydsl.FromString("OutOf(1, 'Org3.member')")
		require.NoError(t, err)

		keyPolicies := []*common.SignaturePolicyEnvelope{keyPolicy1, keyPolicy2, keyPolicy3}

		cps, err := mergeKeyPolicies(keyPolicies)
		require.NoError(t, err)
		require.Len(t, cps, 1)
		require.Len(t, cps[0], 3)
	})

	t.Run("Two different policies - two possible arrangements", func(t *testing.T) {
		keyPolicy1, err := policydsl.FromString("OutOf(2, 'Org1.member', OutOf(1, 'Org2.member', 'Org3.member'))")
		require.NoError(t, err)
		keyPolicy2, err := policydsl.FromString("OutOf(2, 'Org1.member', 'Org2.member', 'Org3.member')")
		require.NoError(t, err)

		keyPolicies := []*common.SignaturePolicyEnvelope{keyPolicy1, keyPolicy2}

		cps, err := mergeKeyPolicies(keyPolicies)
		require.NoError(t, err)
		require.Len(t, cps, 2)
		require.Len(t, cps[0], 2)
		require.Len(t, cps[1], 2)
	})
}

func mockPeer(t *testing.T, name string, mspid string) *dp.Peer {
	sid := &msp.SerializedIdentity{
		Mspid:   mspid,
		IdBytes: []byte(name),
	}
	sidBytes, err := proto.Marshal(sid)
	require.NoError(t, err)
	return &dp.Peer{Identity: sidBytes}
}
