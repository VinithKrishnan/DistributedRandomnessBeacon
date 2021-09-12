// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"encoding/hex"
	"math/big"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/istanbul"
	"github.com/ethereum/go-ethereum/core/types"
	crypto "github.com/ethereum/go-ethereum/crypto"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	ed25519 "github.com/ethereum/go-ethereum/filippo.io/edwards25519"
	elog "github.com/ethereum/go-ethereum/log"
)

var pubKeys map[common.Address]*ed25519.Point
var blspubKeys map[common.Address]*bn256.G2
var blsmemkeys map[common.Address]*bn256.G1
var addrIDMap map[common.Address]int
var idAddrMap map[int]common.Address
var addrs []string
var vals []common.Address
var edKey types.EdKey
var blsKey types.BLSKey
var logdir string

// "0xd1589d31c6674d5540be85baf60850bd39752e40"
// "0x9cc76c660e8679241090e69a967d17ea236e5bd3"
// "0x82ba6627a3453997fc46730e8dd54798f0253f00"

// "0x1d40498b6c909a40cba517e94f37692d54ea604f"

func init() {
	pkPath := "pubkey.json"
	blspkPath := "blspubkey.json"
	blsmkPath := "blsmemkey.json"
	edkeyPath := "key.json"
	blskeyPath := "blskey.json"

	local := true

	logdir = "/home/ubuntu/drb/"
	if local {
		edkeyPath = "/mnt/c/Users/VinithKrishnan/drb-expt/edkeys/k" + strconv.Itoa(0) + ".json"
		blskeyPath = "/mnt/c/Users/VinithKrishnan/drb-expt/blskeys/k" + strconv.Itoa(0) + ".json"

		logdir = "/mnt/c/Users/VinithKrishnan/drb-expt/drb/log/" // should be changed to variable ofr reproducability purpose
	}

	// initializing number of nodes an threshold
	// c.setNumNodesTh(len(vals))

	// Load the nodes from the config file.
	var ednodelist []string
	if err := common.LoadJSON(pkPath, &ednodelist); err != nil {
		elog.Error("Can't load node file", "path", pkPath, "error", err)

	}
	var blspknodelist []string
	if err := common.LoadJSON(blspkPath, &blspknodelist); err != nil {
		elog.Error("Can't load node file", "path", blspkPath, "error", err)

	}
	var blsmknodelist []string
	if err := common.LoadJSON(blsmkPath, &blsmknodelist); err != nil {
		elog.Error("Can't load node file", "path", blsmkPath, "error", err)

	}

	addrs = []string{"d1589d31c6674d5540be85baf60850bd39752e40", "9cc76c660e8679241090e69a967d17ea236e5bd3", "82ba6627a3453997fc46730e8dd54798f0253f00", "1d40498b6c909a40cba517e94f37692d54ea604f"}

	for _, s := range addrs {
		data, _ := hex.DecodeString(s)
		vals = append(vals, common.BytesToAddress(data))
	}

	pubKeys = make(map[common.Address]*ed25519.Point)
	blspubKeys = make(map[common.Address]*bn256.G2)
	blsmemkeys = make(map[common.Address]*bn256.G1)
	addrIDMap = make(map[common.Address]int)
	idAddrMap = make(map[int]common.Address)

	for i, val := range vals {
		addrIDMap[val] = i
		idAddrMap[i] = val
		pubKeys[val] = types.EdStringToPoint(ednodelist[i])
		blspubKeys[val] = types.G2StringToPoint(blspknodelist[i])
		blsmemkeys[val] = types.G1StringToPoint(blsmknodelist[i])
		elog.Trace("Initializing pkeys", "addr", val, "idx", i)
	}
	address := idAddrMap[0]

	// loads the key into the key of the user
	var edstrKey types.EdStringKey
	if err := common.LoadJSON(edkeyPath, &edstrKey); err != nil {
		elog.Error("Can't load node file", "path", edkeyPath, "error", err)

	}
	// log.Info("String Key is:", strKey)
	edKey = types.EdStringToKey(edstrKey)
	elog.Debug("Initializing local key", "addr", address, "pkey", edstrKey.Pkey)

	// var BLSstrKey types.BLSStringKey
	// if err := common.LoadJSON(blskeyPath, &BLSstrKey); err != nil {
	// 	elog.Error("Can't load node file", "path", blskeyPath, "error", err)

	// }
	// // log.Info("String Key is:", strKey)
	// blsKey = types.BLSStringToKey(BLSstrKey)
	// elog.Debug("Initializing local key", "addr", address, "pkey", BLSstrKey.Mkey)
}

func makeBlock(number int64) *types.Block {
	header := &types.Header{
		Difficulty: big.NewInt(0),
		Number:     big.NewInt(number),
		GasLimit:   0,
		GasUsed:    0,
		Time:       0,
	}
	block := &types.Block{}
	return block.WithSeal(header)
}

func newTestProposal() istanbul.Proposal {
	return makeBlock(1)
}

func TestBLSSign(t *testing.T) {
	var pubkeys []*bn256.G2

	for _, value := range blspubKeys {
		pubkeys = append(pubkeys, value)
	}
	sig := crypto.BlsSign(pubkeys, &blsKey.Skey, &blsKey.Mkey, root.Bytes())
}

func TestNewRequest(t *testing.T) {
	testLogger.SetHandler(elog.StdoutHandler)

	N := uint64(4)
	F := uint64(1)

	sys := NewTestSystemWithBackend(N, F)

	close := sys.Run(true)
	defer close()

	request1 := makeBlock(1)
	sys.backends[0].NewRequest(request1)

	<-time.After(1 * time.Second)

	request2 := makeBlock(2)
	sys.backends[0].NewRequest(request2)

	<-time.After(1 * time.Second)

	for _, backend := range sys.backends {
		if len(backend.committedMsgs) != 2 {
			t.Errorf("the number of executed requests mismatch: have %v, want 2", len(backend.committedMsgs))
		}
		if !reflect.DeepEqual(request1.Number(), backend.committedMsgs[0].commitProposal.Number()) {
			t.Errorf("the number of requests mismatch: have %v, want %v", request1.Number(), backend.committedMsgs[0].commitProposal.Number())
		}
		if !reflect.DeepEqual(request2.Number(), backend.committedMsgs[1].commitProposal.Number()) {
			t.Errorf("the number of requests mismatch: have %v, want %v", request2.Number(), backend.committedMsgs[1].commitProposal.Number())
		}
	}
}

func TestQuorumSize(t *testing.T) {
	N := uint64(4)
	F := uint64(1)

	sys := NewTestSystemWithBackend(N, F)
	backend := sys.backends[0]
	c := backend.engine.(*core)

	valSet := c.valSet
	for i := 1; i <= 1000; i++ {
		valSet.AddValidator(common.StringToAddress(string(i)))
		if 2*c.QuorumSize() <= (valSet.Size()+valSet.F()) || 2*c.QuorumSize() > (valSet.Size()+valSet.F()+2) {
			t.Errorf("quorumSize constraint failed, expected value (2*QuorumSize > Size+F && 2*QuorumSize <= Size+F+2) to be:%v, got: %v, for size: %v", true, false, valSet.Size())
		}
	}
}
