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
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/istanbul"
	"github.com/ethereum/go-ethereum/crypto"
	bls381 "github.com/ethereum/go-ethereum/gnark-crypto/ecc/bls12-381"
	"github.com/ethereum/go-ethereum/log"
)

// to start the beacon recovery process
func (c *core) startRecovery(seq uint64, digest common.Hash) {
	go c.sendReconstruct(seq, digest)
}

func reconstructMsg() error {
	// TODO(@sourav) If the node already have the required data it only waits for 2t+1 identical reconstruct message and do not perform any decoding.
	return nil
}

// sendReconstruct sends a reconstruction message for a particular view
func (c *core) sendReconstruct(seq uint64, digest common.Hash) {
	aData, ok := c.nodeAggData[digest]
	c.nodeMu.Lock()
	c.nodeDecidedRoot[seq] = digest
	c.nodeMu.Unlock()
	// log.Debug("Deciding commit cert", "Seq", seq, "nodelist", nodelist, "roothash in bytes", digest.Bytes(), "aggpk", aggpk, "aggsig", aggsign)
	if ok {
		index := c.addrIDMap[c.Address()]

		encEval := aData.EncEvals[index] // aggregated encrypted data
		recData := crypto.ReconstructData(encEval, c.bls381Key.SkeyInv)

		recData.Index = uint64(index)

		irecData := istanbul.RecDataEncode(recData)
		reconstruct, err := Encode(&istanbul.Reconstruct{
			Seq:     seq,
			Root:    digest,
			RecData: irecData,
		})
		if err != nil {
			log.Error("Failed to encode reconstruction message", "number", seq)
			return
		}
		c.broadcast(&message{
			Code: msgReconstruct,
			Msg:  reconstruct,
		})

		dataLen := len(reconstruct)
		sdata := c.logdir + "sdata"
		sdataf, err := os.OpenFile(sdata, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error("Can't open sdataf file", "error", err)
		}
		fmt.Fprintln(sdataf, msgReconstruct, dataLen, -1, c.Now())
		sdataf.Close()
		log.Debug("Broadcast recontstuction message", "number", seq)
	} else {
		log.Info("No private message received from leader yet.")
	}
}

// handleReconstruct reconstructs given enough share has been received
func (c *core) handleReconstruct(msg *message, src istanbul.Validator) error {
	index := c.getIndex(src.Address())
	log.Debug("Handling reconstruction message from", "addr", src.Address(), "index", index)

	var rmsg *istanbul.Reconstruct
	err := msg.Decode(&rmsg)
	if err != nil {
		log.Error("Reconstruct decoding failed", "from", src.Address(), "index", "err", err)
		return errFailedDecodeReconstruct
	}

	rSeq := rmsg.Seq
	root := rmsg.Root
	recon := istanbul.RecDataDecode(rmsg.RecData)
	rIndex := recon.Index

	c.nodeMu.Lock()
	defer c.nodeMu.Unlock()

	if _, ok := c.nodeRecData[rSeq]; !ok {
		c.nodeRecData[rSeq] = make(map[uint64]*crypto.RecData)
	}
	c.nodeRecData[rSeq][rIndex] = &recon
	log.Debug("Added Reconstrcution data for", "number", rSeq, "from", rIndex)

	// Beacon output already available, no need to process further
	if _, rok := c.beacon[rSeq]; rok {
		return errHandleReconstruct
	}
	// check whether root has been decided or not
	_, aok := c.nodeAggData[root]
	if !aok {
		log.Debug("Aggregate Data not yet reconstrcuted!", "root", root)
		return errAggDataNotFound
	}

	// rPkey := c.pubKeys[src.Address()]
	// encShare := aData.EncEvals[rIndex]
	// commit := aData.Points[rIndex]

	// if !crypto.ValidateReconstruct(&rPkey, &encShare, &recon.DecShare, &commit) {
	// 	pkey := new(bls381.G1Affine).FromJacobian(&rPkey).Bytes()
	// 	log.Error("Invalid reconstruct message", "from", pkey, "index", rIndex)
	// 	return errInvalidReconstruct
	// }
	c.addReconstruct(rSeq, rIndex, recon.DecShare)
	return errHandleReconstruct
}

// addReconstruct adds a reconstruction message
func (c *core) addReconstruct(seq, index uint64, share bls381.G1Jac) {

	if _, ok := c.nodeConfShares[seq]; !ok {
		c.nodeConfShares[seq] = make(map[uint64]bls381.G1Jac)
	}
	c.nodeConfShares[seq][index] = share

	if len(c.nodeConfShares[seq]) == c.threshold {
		goutput := crypto.RecoverBeacon(c.nodeConfShares[seq], c.threshold)
		boutput := new(bls381.G1Affine).FromJacobian(&goutput).Bytes()
		output := common.BytesToHash(boutput[:])
		c.beacon[seq] = output
		log.Info("Beacon output for", "number", seq, "output", output.Hex())

		// Sending the beacon output to help others to output that.
		go c.sendBeacon(seq, output)

		// Logging handle prepare time
		rectime := c.logdir + "rectime"
		rectimef, err := os.OpenFile(rectime, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error("Can't open rectimef  file", "error", err)
		}
		fmt.Fprintln(rectimef, seq, output.Hex(), c.Now())
		rectimef.Close()
	}
}
