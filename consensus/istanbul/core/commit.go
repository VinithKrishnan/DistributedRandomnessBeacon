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

func (c *core) sendCommit(root common.Hash) {
	sub := c.current.Subject()
	c.broadcastCommit(sub, root)
}

func (c *core) sendCommitForOldBlock(view *istanbul.View, digest common.Hash) {
	sub := &istanbul.Subject{
		View:   view,
		Digest: digest,
	}
	c.broadcastCommit(sub, digest)
}

func (c *core) broadcastCommit(sub *istanbul.Subject, root common.Hash) {
	logger := c.logger.New("state", c.state)

	encodedCommit, err := Encode(&istanbul.Commit{
		Sub:  sub,
		Root: root,
	})
	if err != nil {
		logger.Error("Failed to encode", "commit", "in boradcastCommit")
		return
	}

	c.broadcast(&message{
		Code: msgCommit,
		Msg:  encodedCommit,
	})

	// Todo(@sourav): Can we do this asynchronously? Also, how about we add a flag here and supress the log when not necessary.
	dataLen := len(encodedCommit)
	sdata := c.logdir + "sdata"
	sdataf, err := os.OpenFile(sdata, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error("Can't open sdataf file", "error", err)
	}
	fmt.Fprintln(sdataf, msgCommit, dataLen, -1,  c.Now())
	sdataf.Close()
}

func (c *core) handleCommit(msg *message, src istanbul.Validator) error {

	// Decode COMMIT message
	var commit *istanbul.Commit
	err := msg.Decode(&commit)
	if err != nil {
		return errFailedDecodeCommit
	}

	// Todo(@sd): We have to disable some checks here.
	if err := c.checkMessage(msgCommit, commit.Sub.View); err != nil {
		return err
	}

	if err := c.verifyCommit(commit, src); err != nil {
		return err
	}
	c.acceptCommit(msg, src)

	// Commit the proposal once we have enough COMMIT messages and we are not in the Committed state.
	// If we already have a proposal, we may have chance to speed up the consensus process
	// by committing the proposal without PREPARE messages.
	if c.current.Commits.Size() >= c.QuorumSize() && c.state.Cmp(StateCommitted) < 0 {
		// c.current.LockHash()
		c.setState(StateCommitted)
		c.sendDecide(commit.Root)
	}
	return nil
}

// verifyCommit verifies if the received COMMIT message is equivalent to our subject
func (c *core) verifyCommit(commit *istanbul.Commit, src istanbul.Validator) error {
	logger := c.logger.New("from", src, "state", c.state)

	sub := c.current.Subject()
	if !reflect.DeepEqual(commit.Sub, sub) {
		logger.Warn("Inconsistent subjects between commit and proposal", "expected", sub, "got", commit)
		return errInconsistentSubject
	}

	return nil
}

func (c *core) acceptCommit(msg *message, src istanbul.Validator) error {
	logger := c.logger.New("from", src, "state", c.state)

	// Add the COMMIT message to current round state
	if err := c.current.Commits.Add(msg); err != nil {
		logger.Error("Failed to record commit message", "msg", msg, "err", err)
		return err
	}

	return nil
}
