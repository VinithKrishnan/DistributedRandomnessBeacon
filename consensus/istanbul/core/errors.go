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

import "errors"

var (
	// errInconsistentSubject is returned when received subject is different from
	// current subject.
	errInconsistentSubject = errors.New("inconsistent subjects")
	// errNotFromProposer is returned when received message is supposed to be from
	// proposer.
	errNotFromProposer = errors.New("message does not come from proposer")
	// errIgnored is returned when a message was ignored.
	errIgnored = errors.New("message is ignored")
	// errFutureMessage is returned when current view is earlier than the
	// view of the received message.
	errFutureMessage = errors.New("future message")

	errInvalidMultiSig = errors.New("Returned MultiSig is invalid")
	// errOldMessage is returned when the received message's view is earlier
	// than current view.
	errOldMessage = errors.New("old message")
	// errInvalidMessage is returned when the message is malformed.
	errInvalidMessage = errors.New("invalid message")
	// errFailedDecodePreprepare is returned when the PRE-PREPARE message is malformed.
	errFailedDecodePreprepare = errors.New("failed to decode PRE-PREPARE")
	// errFailedDecodeAggregate is returned when the AGGREGATE message is malformed.
	errFailedDecodeAggregate = errors.New("failed to decode AGGREGATE")
	// errInvalidAggregate is returned when the AGGREGATE message is malformed
	errInvalidAggregate = errors.New("invalid AGGREGATE")
	// errInvalidCommitment is returned when invalid commitment is sent to the leader
	errInvalidCommitment  = errors.New("invalid COMMITMENT ")
	errInvalidReconstruct = errors.New("invalid  RECONSTRUCTION MSG")
	errAggDataNotFound    = errors.New("Aggregate data not found")
	errRootNotDecided     = errors.New("Root not decided yet")

	errFailedDecodeCommitment  = errors.New("failed to decode COMMITMENT")
	errFailedDecodePrivateData = errors.New("failed to decode PRIVATE DATA")
	errFailedDecodeReconstruct = errors.New("failed to decode RECONSTRUCTION MSG")
	errFailedDecodeBeacon      = errors.New("failed to decode BEACON MSG")

	// dummy errors to avoid propagation of commitment messages
	errHandleCommitment  = errors.New("Sucessdully handled commitment")
	errHandlePrivData    = errors.New("Sucessdully handled private data")
	errHandleReconstruct = errors.New("Sucessdully handled reconstruction message")
	errHandleBeacon      = errors.New("Successfully handled beacon")

	// errFailedDecodePrepare is returned when the PREPARE message is malformed.
	errFailedDecodePrepare = errors.New("failed to decode PREPARE")
	// errFailedDecodeCommit is returned when the COMMIT message is malformed.
	errFailedDecodeCommit = errors.New("failed to decode COMMIT")
	// errFailedDecodeDecide is returned when the COMMIT message is malformed.
	errFailedDecodeDecide = errors.New("failed to decode DECIDE")
	// errFailedDecodeMessageSet is returned when the message set is malformed.
	// errFailedDecodeMessageSet = errors.New("failed to decode message set")
	// errInvalidSigner is returned when the message is signed by a validator different than message sender
	errInvalidSigner = errors.New("message not signed by the sender")

	// var errSendData = errors.New("Unable to send node data")
)
