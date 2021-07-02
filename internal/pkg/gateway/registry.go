/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gateway

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	dp "github.com/hyperledger/fabric-protos-go/discovery"
	"github.com/hyperledger/fabric-protos-go/gossip"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/policies/inquire"
	gossipapi "github.com/hyperledger/fabric/gossip/api"
	gossipcommon "github.com/hyperledger/fabric/gossip/common"
	gossipdiscovery "github.com/hyperledger/fabric/gossip/discovery"
	"github.com/pkg/errors"
)

type Discovery interface {
	Config(channel string) (*dp.ConfigResult, error)
	IdentityInfo() gossipapi.PeerIdentitySet
	PeersForEndorsement(channel gossipcommon.ChannelID, interest *dp.ChaincodeInterest) (*dp.EndorsementDescriptor, error)
	PeersOfChannel(gossipcommon.ChannelID) gossipdiscovery.Members
}

type registry struct {
	localEndorser       *endorser
	discovery           Discovery
	logger              *flogging.FabricLogger
	endpointFactory     *endpointFactory
	remoteEndorsers     map[string]*endorser
	broadcastClients    map[string]*orderer
	tlsRootCerts        map[string][][]byte
	channelsInitialized map[string]bool
	configLock          sync.RWMutex
}

type endorserState struct {
	peer     *dp.Peer
	endorser *endorser
	height   uint64
}

// Returns a set of endorsers that satisfies the endorsement plan for the given chaincode on a channel.
func (reg *registry) endorsers(channel string, chaincode string) ([]*endorser, error) {
	return reg.endorsersWithInterest(
		channel,
		&dp.ChaincodeInterest{
			Chaincodes: []*dp.ChaincodeCall{{
				Name: chaincode,
			}},
		},
		nil,
	)
}

// Returns a set of endorsers that satisfies the endorsement plan for the given chaincode on a channel.
func (reg *registry) endorsersWithInterest(channel string, interest *dp.ChaincodeInterest, keyPolicies []*common.SignaturePolicyEnvelope) ([]*endorser, error) {
	var endorsers []*endorser

	descriptor, err := reg.discovery.PeersForEndorsement(gossipcommon.ChannelID(channel), interest)
	if err != nil {
		return nil, err
	}

	layouts := descriptor.GetLayouts()
	if len(keyPolicies) > 0 {
		layouts, err = filteredLayouts(descriptor, keyPolicies)
		if err != nil {
			return nil, err
		}
	}

	reg.configLock.RLock()
	defer reg.configLock.RUnlock()

	for _, layout := range layouts {
		var receivers []*endorserState // The set of peers the client needs to request endorsements from
		abandonLayout := false
		for group, quantity := range layout.GetQuantitiesByGroup() {
			// Select n remoteEndorsers from each group sorted by block height
			var groupPeers []*endorserState
			for _, peer := range descriptor.GetEndorsersByGroups()[group].GetPeers() {
				// extract block height
				msg := &gossip.GossipMessage{}
				err = proto.Unmarshal(peer.GetStateInfo().GetPayload(), msg)
				if err != nil {
					return nil, err
				}
				height := msg.GetStateInfo().GetProperties().GetLedgerHeight()

				// extract endpoint
				err = proto.Unmarshal(peer.GetMembershipInfo().GetPayload(), msg)
				if err != nil {
					return nil, err
				}
				endpoint := msg.GetAliveMsg().GetMembership().GetEndpoint()

				// find the endorser in the registry for this endpoint
				var endorser *endorser
				if endpoint == reg.localEndorser.address {
					endorser = reg.localEndorser
				} else if e, ok := reg.remoteEndorsers[endpoint]; ok {
					endorser = e
				} else {
					reg.logger.Warnf("Failed to find endorser at %s", endpoint)
					continue
				}

				groupPeers = append(groupPeers, &endorserState{peer: peer, endorser: endorser, height: height})
			}

			// If the number of available endorsers less than the quantity required, try the next layout
			if len(groupPeers) < int(quantity) {
				abandonLayout = true
				break
			}

			// sort by decreasing height
			sort.Slice(groupPeers, sorter(groupPeers, reg.localEndorser.address))

			receivers = append(receivers, groupPeers[0:quantity]...)
		}

		if abandonLayout {
			// try the next layout
			continue
		}

		for _, peer := range receivers {
			endorsers = append(endorsers, peer.endorser)
		}
		return endorsers, nil
	}

	return nil, fmt.Errorf("failed to select a set of endorsers that satisfy the endorsement policy")
}

// endorsersForOrgs returns a set of endorsers owned by the given orgs for the given chaincode on a channel.
func (reg *registry) endorsersForOrgs(channel string, chaincode string, endorsingOrgs []string) ([]*endorser, error) {
	endorsersByOrg := reg.endorsersByOrg(channel, chaincode)

	var endorsers []*endorser
	missingOrgs := []string{}
	for _, required := range endorsingOrgs {
		if e, ok := endorsersByOrg[required]; ok {
			endorsers = append(endorsers, e[0].endorser)
		} else {
			missingOrgs = append(missingOrgs, required)
		}
	}
	if len(missingOrgs) > 0 {
		return nil, fmt.Errorf("failed to find any endorsing peers for org(s): %s", strings.Join(missingOrgs, ", "))
	}

	return endorsers, nil
}

func (reg *registry) endorsersByOrg(channel string, chaincode string) map[string][]*endorserState {
	endorsersByOrg := make(map[string][]*endorserState)

	members := reg.discovery.PeersOfChannel(gossipcommon.ChannelID(channel))

	reg.configLock.RLock()
	defer reg.configLock.RUnlock()

	for _, member := range members {
		pkiid := member.PKIid
		endpoint := member.PreferredEndpoint()

		// find the endorser in the registry for this endpoint
		var endorser *endorser
		if bytes.Equal(pkiid, reg.localEndorser.pkiid) {
			logger.Debugw("Found local endorser", "pkiid", pkiid)
			endorser = reg.localEndorser
		} else if endpoint == "" {
			reg.logger.Warnf("No endpoint for endorser with PKI ID %s", pkiid.String())
			continue
		} else if e, ok := reg.remoteEndorsers[endpoint]; ok {
			logger.Debugw("Found remote endorser", "endpoint", endpoint)
			endorser = e
		} else {
			reg.logger.Warnf("Failed to find endorser at %s", endpoint)
			continue
		}
		for _, installedChaincode := range member.Properties.GetChaincodes() {
			// only consider the peers that have our chaincode installed
			if installedChaincode.GetName() == chaincode {
				endorsersByOrg[endorser.mspid] = append(endorsersByOrg[endorser.mspid], &endorserState{endorser: endorser, height: member.Properties.GetLedgerHeight()})
			}
		}
		for _, es := range endorsersByOrg {
			// sort by decreasing height in each org
			sort.Slice(es, sorter(es, reg.localEndorser.address))
		}
	}
	return endorsersByOrg
}

// evaluator returns a single endorser, preferably from local org, if available
// targetOrgs specifies the orgs that are allowed receive the request, due to private data restrictions
func (reg *registry) evaluator(channel string, chaincode string, targetOrgs []string) (*endorser, error) {
	endorsersByOrg := reg.endorsersByOrg(channel, chaincode)

	// If no targetOrgs are specified (i.e. no restrictions), then populate with all available orgs
	if len(targetOrgs) == 0 {
		for org := range endorsersByOrg {
			targetOrgs = append(targetOrgs, org)
		}
	}
	// Prefer a local org endorser, if present
	if e, ok := endorsersByOrg[reg.localEndorser.mspid]; ok && contains(targetOrgs, reg.localEndorser.mspid) {
		return e[0].endorser, nil
	}
	// Otherwise highest block height peer (first in list) from another org
	var evaluator *endorser
	var maxHeight uint64
	for _, org := range targetOrgs {
		if e, ok := endorsersByOrg[org]; ok && e[0].height > maxHeight {
			evaluator = e[0].endorser
			maxHeight = e[0].height
		}
	}
	if evaluator != nil {
		return evaluator, nil
	}
	return nil, fmt.Errorf("no endorsing peers found for channel: %s", channel)
}

func sorter(e []*endorserState, host string) func(i, j int) bool {
	return func(i, j int) bool {
		if e[i].height == e[j].height {
			// prefer host peer
			return e[i].endorser.address == host
		}
		return e[i].height > e[j].height
	}
}

func contains(slice []string, entry string) bool {
	for _, item := range slice {
		if entry == item {
			return true
		}
	}
	return false
}

// Returns a set of broadcastClients that can order a transaction for the given channel.
func (reg *registry) orderers(channel string) ([]*orderer, error) {
	err := reg.registerChannel(channel)
	if err != nil {
		return nil, err
	}
	var orderers []*orderer

	// Get the config
	config, err := reg.discovery.Config(channel)
	if err != nil {
		return nil, err
	}

	reg.configLock.RLock()
	defer reg.configLock.RUnlock()

	for _, eps := range config.GetOrderers() {
		for _, ep := range eps.Endpoint {
			url := fmt.Sprintf("%s:%d", ep.Host, ep.Port)
			if ord, ok := reg.broadcastClients[url]; ok {
				orderers = append(orderers, ord)
			}
		}
	}

	return orderers, nil
}

func (reg *registry) registerChannel(channel string) error {
	// todo need to handle membership updates
	reg.configLock.Lock() // take a write lock to populate the registry maps
	defer reg.configLock.Unlock()

	if reg.channelsInitialized[channel] {
		return nil
	}
	// get config and peer discovery info for this channel

	// Get the config
	config, err := reg.discovery.Config(channel)
	if err != nil {
		return err
	}
	// get the tlscerts
	for msp, info := range config.GetMsps() {
		reg.tlsRootCerts[msp] = info.GetTlsRootCerts()
	}

	for mspid, eps := range config.GetOrderers() {
		for _, ep := range eps.Endpoint {
			address := fmt.Sprintf("%s:%d", ep.Host, ep.Port)
			if _, ok := reg.broadcastClients[address]; !ok {
				// this orderer is new - connect to it and add to the broadcastClients registry
				tlsRootCerts := reg.tlsRootCerts[mspid]
				orderer, err := reg.endpointFactory.newOrderer(address, mspid, tlsRootCerts)
				if err != nil {
					return err
				}
				reg.broadcastClients[address] = orderer
				reg.logger.Infof("Added orderer to registry: %s", address)
			}
		}
	}

	// get the remoteEndorsers for the channel
	peers := map[string]string{}
	members := reg.discovery.PeersOfChannel(gossipcommon.ChannelID(channel))
	for _, member := range members {
		id := member.PKIid.String()
		peers[id] = member.PreferredEndpoint()
	}
	for mspid, infoset := range reg.discovery.IdentityInfo().ByOrg() {
		for _, info := range infoset {
			pkiid := info.PKIId
			if address, ok := peers[pkiid.String()]; ok {
				// add the peer to the peer map - except the local peer, which seems to have an empty address
				if _, ok := reg.remoteEndorsers[address]; !ok && len(address) > 0 {
					// this peer is new - connect to it and add to the remoteEndorsers registry
					tlsRootCerts := reg.tlsRootCerts[mspid]
					endorser, err := reg.endpointFactory.newEndorser(pkiid, address, mspid, tlsRootCerts)
					if err != nil {
						return err
					}
					reg.remoteEndorsers[address] = endorser
					reg.logger.Infof("Added peer to registry: %s", address)
				}
			}
		}
	}
	reg.channelsInitialized[channel] = true

	return nil
}

func filteredLayouts(descriptor *dp.EndorsementDescriptor, keyPolicies []*common.SignaturePolicyEnvelope) ([]*dp.Layout, error) {
	// first, merge all the SBE policies into one or more comparable principal sets, each of which will satisfy all policies
	sbePrincipalSets, err := mergeKeyPolicies(keyPolicies)
	if err != nil {
		return nil, err
	}

	// Each group represents a Principal.
	// Note we won't have to do this if we put this SBE filter logic in the discovery service itself.
	groupPrincipals, err := endorserGroupPrincipals(descriptor.GetEndorsersByGroups())
	if err != nil {
		return nil, err
	}

	// For each layout, create a comparable principal set, and if it's a superset of at least one SBE principal set, then it's good to keep
	var filteredLayouts []*dp.Layout
	var firstLayoutPrincipalSet inquire.ComparablePrincipalSet
	for i, layout := range descriptor.GetLayouts() {
		layoutPrincipalSet := inquire.ComparablePrincipalSet{}
		for group := range layout.GetQuantitiesByGroup() {
			layoutPrincipalSet = append(layoutPrincipalSet, groupPrincipals[group])
		}
		if i == 0 {
			firstLayoutPrincipalSet = layoutPrincipalSet
		}
		// look at each of the possible SBE principal sets - at least one of them needs to be satisfied by the layout set
		for _, sbePrincipalSet := range sbePrincipalSets {
			if layoutSetSatisfiesSBESet(layoutPrincipalSet, sbePrincipalSet) {
				filteredLayouts = append(filteredLayouts, layout)
				break
			}
		}
	}
	// if none of the layouts satisfied the SBE principal set, then choose a layout and extend it
	if len(filteredLayouts) == 0 && len(firstLayoutPrincipalSet) > 0 {
		// take the first SBE set (because of the limited policy building API in the stub, there's only likely to be one anyway)
		sbePrincipalSet := sbePrincipalSets[0]
		// and merge with the first layout principal set
		mergedGroup := descriptor.Layouts[0].QuantitiesByGroup
		// step through the available groups, if it's in the SBE set, but not in the layout, add it to the layout
		required := len(sbePrincipalSet)
		for group, principal := range groupPrincipals {
			for _, sbePrincipal := range sbePrincipalSet {
				if principal.IsA(sbePrincipal) {
					if _, ok := mergedGroup[group]; !ok {
						mergedGroup[group] = 1
					}
					required--
				}
			}
		}
		if required == 0 {
			// All of the required SBE principals were available in the endorsement descriptor. Use this new layout
			filteredLayouts = append(filteredLayouts, &dp.Layout{QuantitiesByGroup: mergedGroup})
		} else {
			// TODO - if not collections are involved then the remaining principals could be added,
			// but would need to find their peers, and create a new endorsement descriptor with these groups added.
		}
	}

	return filteredLayouts, nil
}

func endorserGroupPrincipals(endorsersByGroup map[string]*dp.Peers) (map[string]*inquire.ComparablePrincipal, error) {
	// Loop through all the groups, and create a comparable principal object.
	groupPrincipals := map[string]*inquire.ComparablePrincipal{}
	for group, peers := range endorsersByGroup {
		// all peers in each group satisfy the same principal - just pick the first one
		sid := &msp.SerializedIdentity{}
		err := proto.Unmarshal(peers.GetPeers()[0].GetIdentity(), sid)
		if err != nil {
			return nil, err
		}
		peerRole := &msp.MSPRole{
			MspIdentifier: sid.GetMspid(),
			Role:          msp.MSPRole_PEER,
		}
		prBytes, err := proto.Marshal(peerRole)
		if err != nil {
			return nil, err
		}
		principal := &msp.MSPPrincipal{
			PrincipalClassification: msp.MSPPrincipal_ROLE,
			Principal:               prBytes,
		}
		groupPrincipals[group] = inquire.NewComparablePrincipal(principal)
	}
	return groupPrincipals, nil
}

func layoutSetSatisfiesSBESet(layoutPrincipalSet, sbePrincipalSet inquire.ComparablePrincipalSet) bool {
	// each principal in the SBE set must be satisfied by the layout set
	for _, sbePrincipal := range sbePrincipalSet {
		found := false
		for _, layoutPrincipal := range layoutPrincipalSet {
			if layoutPrincipal.IsA(sbePrincipal) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// The following helper functions were shamelessly stolen from the discovery service...

func mergeKeyPolicies(keyPolicies []*common.SignaturePolicyEnvelope) (inquire.ComparablePrincipalSets, error) {
	var cpss []inquire.ComparablePrincipalSets

	for _, policy := range keyPolicies {
		isp := inquire.NewInquireableSignaturePolicy(policy)
		var cmpsets inquire.ComparablePrincipalSets
		for _, ps := range isp.SatisfiedBy() {
			cps := inquire.NewComparablePrincipalSet(ps)
			if cps == nil {
				return nil, errors.New("failed creating a comparable principal set")
			}
			cmpsets = append(cmpsets, cps)
		}
		if len(cmpsets) == 0 {
			return nil, errors.New("endorsement policy cannot be satisfied")
		}
		cpss = append(cpss, cmpsets)
	}

	return mergePrincipalSets(cpss)
}

func mergePrincipalSets(cpss []inquire.ComparablePrincipalSets) (inquire.ComparablePrincipalSets, error) {
	// Obtain the first ComparablePrincipalSet first
	var cps inquire.ComparablePrincipalSets
	cps, cpss, err := popComparablePrincipalSets(cpss)
	if err != nil {
		return nil, err
	}

	for _, cps2 := range cpss {
		cps = inquire.Merge(cps, cps2)
	}
	return cps, nil
}

func popComparablePrincipalSets(sets []inquire.ComparablePrincipalSets) (inquire.ComparablePrincipalSets, []inquire.ComparablePrincipalSets, error) {
	if len(sets) == 0 {
		return nil, nil, errors.New("no principal sets remained after SBE filtering")
	}
	cps, cpss := sets[0], sets[1:]
	return cps, cpss, nil
}
