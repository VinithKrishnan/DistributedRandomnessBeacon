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

package istanbul

import (
	// "encoding/hex"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	// ed25519 "github.com/ethereum/go-ethereum/filippo.io/edwards25519"
	bls381 "github.com/ethereum/go-ethereum/gnark-crypto/ecc/bls12-381"

	// "github.com/ethereum/go-ethereum/log"

	"github.com/ethereum/go-ethereum/rlp"
)

// Proposal supports retrieving height and serialized block to be used during Istanbul consensus.
type Proposal interface {
	// Number retrieves the sequence number of this proposal.
	Number() *big.Int

	// Hash retrieves the hash of this proposal.
	Hash() common.Hash

	RBRoot() common.Hash
	Commitments() [][96]byte
	IndexSet() []uint64
	EncEvals() [][48]byte
	UpdateDRB([]uint64, [][96]byte, [][48]byte, common.Hash)

	EncodeRLP(w io.Writer) error

	DecodeRLP(s *rlp.Stream) error

	String() string
}

type Request struct {
	Proposal Proposal
}

// View includes a round number and a sequence number.
// Sequence is the block number we'd like to commit.
// Each round has a number and is composed by 3 steps: preprepare, prepare and commit.
//
// If the given block is not accepted by validators, a round change will occur
// and the validators start a new round with round+1.
type View struct {
	Round    *big.Int
	Sequence *big.Int
}

// EncodeRLP serializes b into the Ethereum RLP format.
func (v *View) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{v.Round, v.Sequence})
}

// DecodeRLP implements rlp.Decoder, and load the consensus fields from a RLP stream.
func (v *View) DecodeRLP(s *rlp.Stream) error {
	var view struct {
		Round    *big.Int
		Sequence *big.Int
	}

	if err := s.Decode(&view); err != nil {
		return err
	}
	v.Round, v.Sequence = view.Round, view.Sequence
	return nil
}

func (v *View) String() string {
	return fmt.Sprintf("{Round: %d, Sequence: %d}", v.Round.Uint64(), v.Sequence.Uint64())
}

// Cmp compares v and y and returns:
//   -1 if v <  y
//    0 if v == y
//   +1 if v >  y
func (v *View) Cmp(y *View) int {
	if v.Sequence.Cmp(y.Sequence) != 0 {
		return v.Sequence.Cmp(y.Sequence)
	}
	if v.Round.Cmp(y.Round) != 0 {
		return v.Round.Cmp(y.Round)
	}
	return 0
}

type Preprepare struct {
	View     *View
	Proposal Proposal
}

type Prepare struct {
	Sub  *Subject
	Root common.Hash
}

type Commit struct {
	Sub  *Subject
	Root common.Hash
}

type Decide struct {
	Sub  *Subject // @sd, not sure what this subject is
	Root common.Hash
}

type Beacon struct {
	Seq    uint64
	Root   common.Hash
	Beacon common.Hash
}

// Reconstruct for the reconstruction phase
type Reconstruct struct {
	Seq     uint64
	Root    common.Hash
	RecData RecData
}

type NodeData struct {
	Round    uint64
	Root     common.Hash // Nil root indicates commitment phase poly. commitment
	Points   [][96]byte
	EncEvals [][48]byte
	Proofs   []NizkProofMixed
	IndexSet []uint64
}

type RoundData struct {
	Round    uint64
	Root     common.Hash
	IndexSet []common.Address
	Proofs   []NizkProofMixed
}

type RecData struct {
	Index    uint64
	DecShare [48]byte
}

type NizkProof struct {
	Commit   [48]byte
	EncEval  [48]byte
	Chal     []byte
	Response []byte
}

type NizkProofMixed struct {
	Commit   [96]byte
	EncEval  [48]byte
	Chal     []byte
	Response []byte
}

func G1JacToBytes(points []bls381.G1Jac) [][48]byte {
	total := len(points)
	var (
		ipoints = make([][48]byte, total)
		g1Aff   bls381.G1Affine
	)
	for i := 0; i < total; i++ {
		ipoints[i] = g1Aff.FromJacobian(&points[i]).Bytes()
	}
	return ipoints
}

func G2JacToBytes(points []bls381.G2Jac) [][96]byte {
	total := len(points)
	var (
		ipoints = make([][96]byte, total)
		g2Aff   bls381.G2Affine
	)
	for i := 0; i < total; i++ {
		ipoints[i] = g2Aff.FromJacobian(&points[i]).Bytes()
	}
	return ipoints
}

func BytesToG1Jac(ipoints [][48]byte) []bls381.G1Jac {
	total := len(ipoints)
	var (
		points = make([]bls381.G1Jac, total)
		g1Aff  bls381.G1Affine
	)
	for i := 0; i < total; i++ {
		g1Aff.SetBytes(ipoints[i][:])
		points[i].FromAffine(&g1Aff)
	}
	return points
}

func BytesToG2Jac(ipoints [][96]byte) []bls381.G2Jac {
	total := len(ipoints)
	var (
		points = make([]bls381.G2Jac, total)
		g2Aff  bls381.G2Affine
	)
	for i := 0; i < total; i++ {
		g2Aff.SetBytes(ipoints[i][:])
		points[i].FromAffine(&g2Aff)
	}
	return points
}

func RecDataEncode(recData crypto.RecData) RecData {
	return RecData{
		Index:    recData.Index,
		DecShare: new(bls381.G1Affine).FromJacobian(&recData.DecShare).Bytes(),
	}
}

func RecDataDecode(recData RecData) crypto.RecData {
	var decShare bls381.G1Affine
	decShare.SetBytes(recData.DecShare[:])
	return crypto.RecData{
		Index:    recData.Index,
		DecShare: *new(bls381.G1Jac).FromAffine(&decShare),
	}
}

func RoundDataEncode(rData crypto.RoundData) RoundData {
	proofs := rData.Proofs
	total := len(proofs)
	var iproofs = make([]NizkProofMixed, total)
	for i := 0; i < total; i++ {
		iproofs[i] = getIProofMixed(proofs[i])
	}
	return RoundData{
		Round:    rData.Round,
		Root:     rData.Root,
		IndexSet: rData.IndexSet,
		Proofs:   iproofs,
	}
}

func RoundDataDecode(rData RoundData) crypto.RoundData {
	iproofs := rData.Proofs
	total := len(iproofs)
	proofs := make([]crypto.NizkProofMixed, total)
	for i := 0; i < total; i++ {
		proofs[i] = getCProofMixed(iproofs[i])
	}
	return crypto.RoundData{
		Round:    rData.Round,
		Root:     rData.Root,
		IndexSet: rData.IndexSet,
		Proofs:   proofs,
	}
}

func NodeDataEncode(nData crypto.NodeData) NodeData {
	points := nData.Points
	total := len(points)
	encEvals := nData.EncEvals
	proofs := nData.Proofs
	indexset := nData.IndexSet

	var (
		iPoints   = make([][96]byte, total)
		iEncEvals = make([][48]byte, total)
		iProofs   = make([]NizkProofMixed, total)
		g1Aff     bls381.G1Affine
		g2Aff     bls381.G2Affine
	)

	for i := 0; i < total; i++ {
		iPoints[i] = g2Aff.FromJacobian(&points[i]).Bytes()
		iEncEvals[i] = g1Aff.FromJacobian(&encEvals[i]).Bytes()
		iProofs[i] = getIProofMixed(proofs[i])
	}

	return NodeData{
		Round:    nData.Round,
		Root:     nData.Root,
		Points:   iPoints,
		EncEvals: iEncEvals,
		Proofs:   iProofs,
		IndexSet: indexset,
	}
	// for i := 0; i < total; i++ {
	// 	log.Info("pcompare", "cp", hex.EncodeToString(points[i].Bytes()), "ip", hex.EncodeToString(iPoints[i]))
	// 	log.Info("ccompare", "cc", hex.EncodeToString(encEvals[i].Bytes()), "ic", hex.EncodeToString(iEncEvals[i]))
	// }
}

func getIProof(proof crypto.NizkProof) NizkProof {
	return NizkProof{
		Commit:   new(bls381.G1Affine).FromJacobian(&proof.Commit).Bytes(),
		EncEval:  new(bls381.G1Affine).FromJacobian(&proof.EncEval).Bytes(),
		Chal:     proof.Chal.Bytes(),
		Response: proof.Response.Bytes(),
	}
	// log.Info("compar", "cp", hex.EncodeToString(proof.Commit.Bytes()), "ci", hex.EncodeToString(iproof.Commit))
	// log.Info("compar", "ce", hex.EncodeToString(proof.EncEval.Bytes()), "ie", hex.EncodeToString(iproof.EncEval))
	// log.Info("compar", "cc", hex.EncodeToString(proof.Chal.Bytes()), "ci", hex.EncodeToString(iproof.Chal))
	// log.Info("compar", "cr", hex.EncodeToString(proof.Response.Bytes()), "ci", hex.EncodeToString(iproof.Response))
}

func getIProofMixed(proof crypto.NizkProofMixed) NizkProofMixed {
	return NizkProofMixed{
		Commit:   (new(bls381.G2Affine).FromJacobian(&proof.Commit).Bytes()),
		EncEval:  (new(bls381.G1Affine).FromJacobian(&proof.EncEval).Bytes()),
		Chal:     proof.Chal.Bytes(),
		Response: proof.Response.Bytes(),
	}
	// log.Info("compar", "cp", hex.EncodeToString(proof.Commit.Bytes()), "ci", hex.EncodeToString(iproof.Commit))
	// log.Info("compar", "ce", hex.EncodeToString(proof.EncEval.Bytes()), "ie", hex.EncodeToString(iproof.EncEval))
	// log.Info("compar", "cc", hex.EncodeToString(proof.Chal.Bytes()), "ci", hex.EncodeToString(iproof.Chal))
	// log.Info("compar", "cr", hex.EncodeToString(proof.Response.Bytes()), "ci", hex.EncodeToString(iproof.Response))
}

func getCProof(proof NizkProof) crypto.NizkProof {
	var (
		comAff bls381.G1Affine
		encAff bls381.G1Affine
	)
	comAff.SetBytes(proof.Commit[:])
	encAff.SetBytes(proof.EncEval[:])
	return crypto.NizkProof{
		Commit:   *new(bls381.G1Jac).FromAffine(&comAff),
		EncEval:  *new(bls381.G1Jac).FromAffine(&encAff),
		Chal:     new(big.Int).SetBytes(proof.Chal),
		Response: new(big.Int).SetBytes(proof.Response),
	}
}

func getCProofMixed(proof NizkProofMixed) crypto.NizkProofMixed {
	var (
		comAff bls381.G2Affine
		encAff bls381.G1Affine
	)
	comAff.SetBytes(proof.Commit[:])
	encAff.SetBytes(proof.EncEval[:])
	return crypto.NizkProofMixed{
		Commit:   *new(bls381.G2Jac).FromAffine(&comAff),
		EncEval:  *new(bls381.G1Jac).FromAffine(&encAff),
		Chal:     new(big.Int).SetBytes(proof.Chal),
		Response: new(big.Int).SetBytes(proof.Response),
	}
}

func NodeDataDecode(nData NodeData) crypto.NodeData {
	points := nData.Points
	total := len(points)
	encEvals := nData.EncEvals
	proofs := nData.Proofs
	indexset := nData.IndexSet

	var (
		cPoints   = make([]bls381.G2Jac, total)
		cEncEvals = make([]bls381.G1Jac, total)
		cProofs   = make([]crypto.NizkProofMixed, total)
		comAff    bls381.G2Affine
		encAff    bls381.G1Affine
	)

	for i := 0; i < total; i++ {
		encAff.SetBytes(encEvals[i][:])
		comAff.SetBytes(points[i][:])
		cPoints[i].FromAffine(&comAff)
		cEncEvals[i].FromAffine(&encAff)
		cProofs[i] = getCProofMixed(proofs[i])
	}
	return crypto.NodeData{
		Round:    nData.Round,
		Root:     nData.Root,
		Points:   cPoints,
		EncEvals: cEncEvals,
		Proofs:   cProofs,
		IndexSet: indexset,
	}
}

// Commitment is sent during the commitment phase
type Commitment struct {
	NData NodeData
}

// PrivateData has the data a leader privately sends to a node
type PrivateData struct {
	RData RoundData
}

// EncodeRLP serializes b into the Ethereum RLP format.
func (b *Preprepare) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{b.View, b.Proposal})
}

// DecodeRLP implements rlp.Decoder, and load the consensus fields from a RLP stream.
func (b *Preprepare) DecodeRLP(s *rlp.Stream) error {
	var preprepare struct {
		View     *View
		Proposal *types.Block
	}

	if err := s.Decode(&preprepare); err != nil {
		return err
	}
	b.View, b.Proposal = preprepare.View, preprepare.Proposal

	return nil
}

type Subject struct {
	View   *View
	Digest common.Hash
}

// EncodeRLP serializes b into the Ethereum RLP format.
func (b *Subject) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{b.View, b.Digest})
}

// DecodeRLP implements rlp.Decoder, and load the consensus fields from a RLP stream.
func (b *Subject) DecodeRLP(s *rlp.Stream) error {
	var subject struct {
		View   *View
		Digest common.Hash
	}

	if err := s.Decode(&subject); err != nil {
		return err
	}
	b.View, b.Digest = subject.View, subject.Digest
	return nil
}

func (b *Subject) String() string {
	return fmt.Sprintf("{View: %v, Digest: %v}", b.View, b.Digest.String())
}
