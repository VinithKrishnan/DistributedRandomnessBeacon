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
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/istanbul"
	"github.com/ethereum/go-ethereum/log"
)

func (c *core) sendDecide(root common.Hash) {
	sub := c.current.Subject()
	c.current.SentDecide = true
	c.broadcastDecide(sub, root)
}

func (c *core) broadcastDecide(sub *istanbul.Subject, root common.Hash) {
	logger := c.logger.New("state", c.state)

	encodedDecide, err := Encode(&istanbul.Decide{
		Sub:  sub,
		Root: root,
	})
	if err != nil {
		logger.Error("Failed to encode", "commit", "in boradcastCommit")
		return
	}

	c.broadcast(&message{
		Code: msgDecide,
		Msg:  encodedDecide,
	})

	// Todo(@sourav): Can we do this asynchronously? Also, how about we add a flag here and supress the log when not necessary.
	encodeLen := len(encodedDecide)
	sdata := c.logdir + "sdata"
	sdataf, err := os.OpenFile(sdata, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error("Can't open sdataf file", "error", err)
	}
	fmt.Fprintln(sdataf, msgDecide, encodeLen, -1,  c.Now())
	sdataf.Close()
}

func (c *core) handleDecide(msg *message, src istanbul.Validator) error {

	// Decode COMMIT message
	var decide *istanbul.Decide
	err := msg.Decode(&decide)
	if err != nil {
		return errFailedDecodeDecide
	}

	if err := c.checkMessage(msgDecide, decide.Sub.View); err != nil {
		return err
	}

	if err := c.verifyDecide(decide, src); err != nil {
		return err
	}
	c.acceptDecide(msg, src)

	// Commit the proposal once we have enough COMMIT messages and we are not in the Committed state.
	//
	// If we already have a proposal, we may have chance to speed up the consensus process
	// by committing the proposal without PREPARE messages.
	if c.state.Cmp(StateDecided) < 0 {
		numDecides := c.current.Decides.Size()
		root := decide.Root
		// Amplification step
		if !c.current.SentDecide && numDecides > c.WeakQuorumSize() {
			c.sendDecide(root)
			log.Info("Sending Decide due to amplification step")
		}
		if numDecides >= c.QuorumSize() {
			c.decide(decide.Sub.View.Sequence.Uint64(), root)
			log.Debug("Decided on a block with", "root", root)
		}
	}
	return nil
}

// verifyCommit verifies if the received COMMIT message is equivalent to our subject
func (c *core) verifyDecide(decide *istanbul.Decide, src istanbul.Validator) error {
	logger := c.logger.New("from", src, "state", c.state)

	sub := c.current.Subject()
	if !reflect.DeepEqual(decide.Sub, sub) {
		logger.Warn("Inconsistent subjects between decide and proposal", "expected", sub, "got", decide)
		return errInconsistentSubject
	}

	return nil
}

func (c *core) acceptDecide(msg *message, src istanbul.Validator) error {
	logger := c.logger.New("from", src, "state", c.state)

	// Add the DECIDE message to current round state
	if err := c.current.Decides.Add(msg); err != nil {
		logger.Error("Failed to record decide message", "msg", msg, "err", err)
		return err
	}

	return nil
}
