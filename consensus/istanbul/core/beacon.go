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
	"github.com/ethereum/go-ethereum/log"
)

// to start the beacon recovery process
func (c *core) sendBeacon(seq uint64, beacon common.Hash) {
	go c.broadcastBeacon(seq, beacon)
}

func (c *core) broadcastBeacon(seq uint64, output common.Hash) {
	beacon, err := Encode(&istanbul.Beacon{
		Seq:    seq,
		Beacon: output,
	})

	if err != nil {
		log.Error("Failed to encode beacon message", "number", seq, "output", output)
		return
	}

	c.broadcast(&message{
		Code: msgBeacon,
		Msg:  beacon,
	})

	dataLen := len(beacon)
	sdata := c.logdir + "sdata"
	sdataf, err := os.OpenFile(sdata, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error("Can't open sdataf file", "error", err)
	}
	fmt.Fprintln(sdataf, msgBeacon, dataLen, -1, c.Now())
	sdataf.Close()
	log.Debug("Broadcast recontstuction message", "number", seq)
}

func (c *core) handleBeacon(msg *message, src istanbul.Validator) error {

	var bmsg *istanbul.Beacon
	err := msg.Decode(&bmsg)
	if err != nil {
		log.Error("Beacon decoding failed", "from", src.Address(), "err", err)
		return errFailedDecodeBeacon
	}

	seq := bmsg.Seq
	c.nodeMu.Lock()
	defer c.nodeMu.Unlock()
	if _, bok := c.beacon[seq]; bok {
		return errHandleBeacon
	}

	if _, sok := c.preBeacon[seq]; !sok {
		c.preBeacon[seq] = make(map[common.Hash]int)
	}

	output := bmsg.Beacon
	freqData := c.preBeacon[seq]
	if freq, rok := freqData[output]; rok {
		freqData[output] = freq + 1
		if freq+1 > c.threshold {
			c.beacon[seq] = output
			log.Info("Beacon output for", "number", seq, "output", output.Hex())

			rectime := c.logdir + "rectime"
			rectimef, err := os.OpenFile(rectime, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Error("Can't open rectimef  file", "error", err)
			}
			fmt.Fprintln(rectimef, seq, output.Hex(), c.Now())
			rectimef.Close()
		}
		return errHandleBeacon
	}
	freqData[output] = 1
	return errHandleBeacon
}
