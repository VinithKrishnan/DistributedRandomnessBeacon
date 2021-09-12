package crypto

import (
	"crypto/rand"
	// "crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	// "encoding/hex"
	"errors"
	"math/big"

	rnd "math/rand"

	"github.com/ethereum/go-ethereum/common"
	bls381 "github.com/ethereum/go-ethereum/gnark-crypto/ecc/bls12-381"
	fr "github.com/ethereum/go-ethereum/gnark-crypto/ecc/bls12-381/fr"

	"github.com/ethereum/go-ethereum/log"
	// "github.com/ethereum/go-ethereum/onrik/gomerkle"
)

var GROUP_ORDER = fr.Modulus()

var (
	errInvalidSanityCheck = errors.New("sanity check failed")
	errInvalidPolyCommit  = errors.New("Invalid polynomial commitment")
	errInvalidNIZK        = errors.New("Invalid NIZK proof")
)

// NodeData implements the polynomial commitment type
type NodeData struct {
	Round    uint64
	Root     common.Hash
	Points   G2Points
	EncEvals G1Points
	Proofs   NizkProofsMixed
	IndexSet []uint64
}

// RoundData stores data received from the leader
type RoundData struct {
	Round    uint64
	Root     common.Hash
	IndexSet []common.Address
	Proofs   NizkProofsMixed
}

// NizkProof is a zk-knowledege of dleq
type NizkProof struct {
	Commit   bls381.G1Jac
	EncEval  bls381.G1Jac
	Chal     *big.Int
	Response *big.Int
}

// NizkProofMixed is a zk-knowledege of dleq during the commitment phase
type NizkProofMixed struct {
	Commit   bls381.G2Jac
	EncEval  bls381.G1Jac
	Chal     *big.Int
	Response *big.Int
}

// RecData is the reconstruction message of a node
type RecData struct {
	Index    uint64
	DecShare bls381.G1Jac
}

type NizkProofs []NizkProof
type NizkProofsMixed []NizkProofMixed
type G1Points []bls381.G1Jac
type G2Points []bls381.G2Jac
type Scalars []fr.Element

var G, H, ONE = BasePoints()
var (
	affineG    = *new(bls381.G2Affine).FromJacobian(G)
	affineH    = *new(bls381.G1Affine).FromJacobian(H)
	affineONE  = *new(bls381.G2Affine).FromJacobian(ONE)
	xPowers    [][]fr.Element             // To pre-compute the powers of x
	lagInverse = make(map[int]fr.Element) // To store the inverse of lagrange denominators
	RANDCODE   []fr.Element
)

// BasePoints helps initialize G,H and ONE
func BasePoints() (*bls381.G2Jac, *bls381.G1Jac, *bls381.G2Jac) {
	rg := rnd.New(rnd.NewSource(int64(10)))
	rh := rnd.New(rnd.NewSource(int64(1027)))
	vg := new(big.Int).Rand(rg, GROUP_ORDER)
	vh := new(big.Int).Rand(rh, GROUP_ORDER)
	h, g, _, _ := bls381.Generators()
	return g.ScalarMultiplication(&g, vg), h.ScalarMultiplication(&h, vh), new(bls381.G2Jac).ScalarMultiplication(&g, big.NewInt(0))
}

// InitXPowers initializes xPowers
func InitXPowers(total int) {
	xPowers = make([][]fr.Element, total)
	var (
		x    fr.Element
		xPow fr.Element
	)
	for i := 1; i <= total; i++ {
		x.SetBigInt(big.NewInt(int64(i)))
		xPow.Set(&x)
		xPowers[i-1] = make([]fr.Element, total+1)
		xPowers[i-1][0].SetBigInt(big.NewInt(1))
		for ii := 1; ii <= total; ii++ {
			xPowers[i-1][ii].Set(&xPow)
			xPow.Mul(&xPow, &x)
		}
	}
}

// InitLagInverse compute inverses of constants and store them
func InitLagInverse(total int) {
	var x fr.Element
	for i := 1; i <= total; i++ {
		for ii := 1; ii <= total; ii++ {
			if i != ii {
				x.SetBigInt(big.NewInt(int64(i - ii)))
				lagInverse[i-ii] = *new(fr.Element).Inverse(&x)
			}
		}
	}
}

// InitRandomCode initializes the random codeword
func InitRandomCode(total, ths int) {
	RANDCODE = RandomCodeword(total, ths)
}

// Polynomial is defined as a list of scalars
type Polynomial struct {
	coeffs []fr.Element
}

// // Eval returns the polynomial evaluation point
// func (p Polynomial) Eval(arg int) *ed25519.Scalar {
// 	x := BintToScalar(big.NewInt(int64(arg)))
// 	result := ed25519.NewScalar().Add(p.coeffs[0], ed25519.NewScalar().Multiply(x, p.coeffs[1]))
// 	xPow := ed25519.NewScalar().Set(x)
// 	for i := 2; i < len(p.coeffs); i++ {
// 		xPow.Multiply(xPow, x)
// 		result.Add(result, ed25519.NewScalar().Multiply(p.coeffs[i], xPow))
// 	}
// 	return result
// }

// Eval returns the polynomial evaluation point
// TODO(@sourav): Check whether returning big.Int is better than returning an fr.Element
func (p Polynomial) Eval(arg int) *big.Int {
	xPows := xPowers[arg-1]
	var (
		result fr.Element
		temp   fr.Element
	)
	plen := len(p.coeffs)
	result.Add(&p.coeffs[0], temp.Mul(&xPows[1], &p.coeffs[1]))
	for i := 2; i < plen; i++ {
		result.Add(&result, temp.Mul(&p.coeffs[i], &xPows[i]))
	}
	return result.ToBigIntRegular(big.NewInt(0))
}

// Random returns a random scalar
func Random() fr.Element {
	var e fr.Element
	v, _ := rand.Int(rand.Reader, GROUP_ORDER)
	e.SetBigInt(v)
	return e
}

// RandomWithSecret returns a polynomial with random coefficients from Zq.
// p(x) = c_0 + c_1*x + ... c_{degree} * x^{degree}
func RandomWithSecret(degree int, secret *fr.Element) Polynomial {
	var (
		coeffs = make([]fr.Element, degree+1)
		v      *big.Int
	)
	coeffs[0].Set(secret)
	for i := 1; i <= degree; i++ {
		v, _ = rand.Int(rand.Reader, GROUP_ORDER)
		coeffs[i].SetBigInt(v)
	}
	return Polynomial{coeffs}
}

// RandomPoly similar to above function . But randomly chooses secret Scalar parameter
func RandomPoly(degree int) Polynomial {
	var (
		coeffs = make([]fr.Element, degree+1)
		v      *big.Int
	)
	for i := 0; i <= degree; i++ {
		v, _ = rand.Int(rand.Reader, GROUP_ORDER)
		coeffs[i].SetBigInt(v)
	}
	return Polynomial{coeffs}
}

// KeyGen generates a fresh ed25519 keypair (sk, pk = h^sk) for a participant in the PVSS protocol
func KeyGen() (*big.Int, *bls381.G2Jac) {
	var pubKey bls381.G2Jac
	secKey, _ := rand.Int(rand.Reader, GROUP_ORDER)
	pubKey.ScalarMultiplication(&pubKey, secKey)
	return secKey, &pubKey
}

// ShareRandomSecret secret shares a random data
// func ShareRandomSecret(pubKeys Points, total, ths int, secret *ed25519.Scalar) NodeData {
// 	var (
// 		shares      = make(Scalars, total)
// 		commitments = make(Points, total)
// 		encEvals    = make(Points, total)
// 	)
// 	// creates a random polynomial
// 	poly := RandomWithSecret(ths-1, secret)
// 	// computes commitments, encrypted shares for each party
// 	for i := 1; i <= total; i++ {
// 		share := poly.Eval(i)
// 		shares[i-1] = *ed25519.NewScalar().Set(share)
// 		encEvals[i-1] = *ed25519.NewIdentityPoint().ScalarMult(share, &pubKeys[i-1])
// 		commitments[i-1] = *ed25519.NewIdentityPoint().ScalarMult(share, &G)
// 	}
// 	// generating proof for each party
// 	proofs := ProveShareCorrectness(shares, commitments, encEvals, pubKeys)
// 	return NodeData{
// 		Points:   commitments,
// 		EncEvals: encEvals,
// 		Proofs:   proofs,
// 	}
// }

// ShareRandomSecret secret shares a random data
// TODO(@sourav) check the difference between Montgomery and Regular form, and pick on depending upon the efficiency
func ShareRandomSecret(pubKeys G1Points, total, ths int, secret fr.Element) NodeData {
	var (
		shares      = make([]fr.Element, total)
		commitments = make([]bls381.G2Jac, total)
		encEvals    = make([]bls381.G1Jac, total)
		share       *big.Int
	)
	// creates a random polynomial
	poly := RandomWithSecret(ths-1, &secret)
	// computes commitments, encrypted shares for each party
	for i := 1; i <= total; i++ {
		share = poly.Eval(i)
		shares[i-1].SetBigInt(share)
		encEvals[i-1].ScalarMultiplication(&pubKeys[i-1], share)
		commitments[i-1].ScalarMultiplication(G, share)
	}
	// generating proof for each party
	proofs := ProveShareCorrectness(shares, commitments, encEvals, pubKeys)
	return NodeData{
		Points:   commitments,
		EncEvals: encEvals,
		Proofs:   proofs,
	}
}

// ReconstructData returns the data for the reconstruction phase
func ReconstructData(enc bls381.G1Jac, secKeyInv *big.Int) RecData {
	dec := DecryptShare(&enc, secKeyInv)
	// chal, res := DleqProve(H, dec, &pkey, &enc, secKey)
	return RecData{
		DecShare: *dec,
		// Proof: NizkProof{
		// 	Commit:   pkey,
		// 	EncEval:  enc,
		// 	Chal:     chal,
		// 	Response: res,
		// },
	}
}

// DecryptShare encryptedshare * secret_key.inverse()
func DecryptShare(share *bls381.G1Jac, secKeyInv *big.Int) *bls381.G1Jac {
	var dshare bls381.G1Jac
	return dshare.ScalarMultiplication(share, secKeyInv)
}

// DleqVerifyMixed verifies a sequene of discrete logarithms
func DleqVerifyMixed(numProofs int, proofs NizkProofsMixed, h G1Points) bool {
	var (
		temp11 bls381.G2Jac
		a1     bls381.G2Jac
		temp21 bls381.G1Jac
		a2     bls381.G1Jac
		proof  NizkProofMixed
	)
	for i := 0; i < numProofs; i++ {
		// each proof contains (Commit, EncEval, Chal, Response)
		proof = proofs[i]
		temp11.ScalarMultiplication(&proof.Commit, proof.Chal)
		a1.ScalarMultiplication(G, proof.Response)
		a1.AddAssign(&temp11)
		// temp11 := ed25519.NewIdentityPoint().ScalarMult(&proof.Chal, &proof.Commit)
		// a1 := ed25519.NewIdentityPoint().ScalarMult(&proof.Response, &G)
		// a1.Add(temp11, a1)

		// temp21 := ed25519.NewIdentityPoint().ScalarMult(&proof.Chal, &proof.EncEval)
		// a2 := ed25519.NewIdentityPoint().ScalarMult(&proof.Response, &h[i])
		// a2.Add(temp21, a2)

		temp21.ScalarMultiplication(&proof.EncEval, proof.Chal)
		a2.ScalarMultiplication(&h[i], proof.Response)
		a2.AddAssign(&temp21)

		eLocal := DleqDeriveChalMixed(&proof.Commit, &a1, &proof.EncEval, &a2)
		// log.Info("Chal DleqVerifyMixed", "eLocal", hex.EncodeToString(eLocal.Bytes()),
		// 	"chal", hex.EncodeToString(proof.Chal.Bytes()), "i", i, "response", hex.EncodeToString(proof.Response.Bytes()),
		// 	"a2", hex.EncodeToString(new(bls381.G1Affine).FromJacobian(&a2).Marshal()),
		// 	"a1", hex.EncodeToString(new(bls381.G2Affine).FromJacobian(&a1).Marshal()))

		if eLocal.Cmp(proof.Chal) != 0 {
			return false
		}
	}
	return true
}

// DleqBatchVerify same as DleqVerify except a single chal is computed for the entire challenge
// func DleqBatchVerify(g Points, h Points, x Points, y Points, e ed25519.Scalar, z Scalars) bool {
// 	n := len(g)
// 	if n != len(x) || n != len(h) || n != len(y) || n != len(z) {
// 		panic("Lenghts are not equal(DLEQ Verify)!")
// 	}
// 	var a1 Points
// 	for i := 0; i < n; i++ {
// 		a1 = append(a1, g[i].Mul(z[i]).Add(x[i].Mul(e)))
// 	}
// 	var a2 Points
// 	for i := 0; i < n; i++ {
// 		a2 = append(a2, h[i].Mul(z[i]).Add(y[i].Mul(e)))
// 	}
// 	eLocal := DleqDeriveBatchChal(x, y, a1, a2)
// 	return reflect.DeepEqual(e, eLocal)
// }

// DleqDeriveBatchChal computes the challenge using the entire batch
// func DleqDeriveBatchChal(x Points, y Points, a1 Points, a2 Points) ed25519.Scalar {
// 	n := len(x)
// 	var bytestring []byte
// 	for i := 0; i < n; i++ {
// 		bytestring = append(bytestring, x[i].Bytes()...)
// 		bytestring = append(bytestring, y[i].Bytes()...)
// 		bytestring = append(bytestring, a1[i].Bytes()...)
// 		bytestring = append(bytestring, a2[i].Bytes()...)
// 	}
// 	hash := sha512.New()
// 	hash.Write(bytestring)
// 	bs := hash.Sum(nil)
// 	return ed25519.ScalarReduce(bs)
// }

// ProveShareCorrectness returns commitments to the shares and a NIZK proof
// (DLEQ) proofing that the encrypted_shares are correctly derived.
func ProveShareCorrectness(shares []fr.Element, commits []bls381.G2Jac, encEvals, pubKeys []bls381.G1Jac) NizkProofsMixed {
	n := len(shares)
	// Validate length of each vector
	if n != len(commits) || n != len(pubKeys) || n != len(encEvals) {
		panic("Lengths not equal!")
	}
	// Compute proof of each node
	var proofs NizkProofsMixed
	for j := 0; j < n; j++ {
		chal, res := DleqProveMixed(G, &commits[j], &pubKeys[j], &encEvals[j], shares[j])
		proofs = append(proofs, NizkProofMixed{
			Commit:   commits[j],
			EncEval:  encEvals[j],
			Chal:     chal,
			Response: res,
		})
	}
	return proofs
}

// DleqProve proves equality of discrete log for a single tuple
func DleqProve(g, h, x, y *bls381.G1Jac, alpha *big.Int) (*big.Int, *big.Int) {
	var (
		a1 bls381.G1Jac
		a2 bls381.G1Jac
		e  *big.Int
		w  *big.Int
	)
	// w random element  from Zq
	w, _ = rand.Int(rand.Reader, GROUP_ORDER)
	a1.ScalarMultiplication(g, w)
	a2.ScalarMultiplication(h, w)
	e = DleqDeriveChal(x, y, &a1, &a2)
	w.Sub(w, new(big.Int).Mul(e, alpha))
	return e, w.Mod(w, GROUP_ORDER) // TODO(@sourav) double check this for correctnes
}

// DleqProveMixed to compute DleqProve on mixed
// TODO(@sourav) Change the fr.Element to big.Int
func DleqProveMixed(g, x *bls381.G2Jac, h, y *bls381.G1Jac, alpha fr.Element) (*big.Int, *big.Int) {
	var (
		a1 bls381.G2Jac
		a2 bls381.G1Jac
		e  *big.Int
		w  *big.Int
	)
	// w random element  from Zq
	w, _ = rand.Int(rand.Reader, GROUP_ORDER)
	a1.ScalarMultiplication(g, w)
	a2.ScalarMultiplication(h, w)
	e = DleqDeriveChalMixed(x, &a1, y, &a2)
	w.Sub(w, new(big.Int).Mul(e, alpha.ToBigIntRegular(new(big.Int))))

	// log.Info("Chal ProveShareCorrectness", "e", hex.EncodeToString(e.Bytes()),
	// 	"a2", hex.EncodeToString(new(bls381.G1Affine).FromJacobian(&a2).Marshal()),
	// 	"a1", hex.EncodeToString(new(bls381.G2Affine).FromJacobian(&a1).Marshal()))

	return e, w.Mod(w, GROUP_ORDER) // TODO(@sourav) double check this for correctnes
}

// DleqDeriveChal computes the dleq challenge
func DleqDeriveChal(x, y, a1, a2 *bls381.G1Jac) *big.Int {
	var (
		bytestring []byte
		e          fr.Element
		g1Aff      bls381.G1Affine
		tempByte   []byte
	)
	tempByte = g1Aff.FromJacobian(x).Marshal()
	bytestring = append(bytestring, tempByte...)
	bytestring = append(bytestring, g1Aff.FromJacobian(y).Marshal()...)
	bytestring = append(bytestring, g1Aff.FromJacobian(a1).Marshal()...)
	bytestring = append(bytestring, g1Aff.FromJacobian(a2).Marshal()...)

	hash := sha512.New()
	hash.Write(bytestring)
	bs := hash.Sum(nil)
	return e.SetBytes(bs).ToBigIntRegular(big.NewInt(0))
}

// DleqDeriveChalMixed Compute challenge on mixed group
func DleqDeriveChalMixed(x, a1 *bls381.G2Jac, y, a2 *bls381.G1Jac) *big.Int {
	var (
		bytestring []byte
		e          fr.Element
		g1Aff      bls381.G1Affine
		g2Aff      bls381.G2Affine
	)

	bytestring = append(bytestring, g2Aff.FromJacobian(x).Marshal()...)
	bytestring = append(bytestring, g1Aff.FromJacobian(y).Marshal()...)
	bytestring = append(bytestring, g2Aff.FromJacobian(a1).Marshal()...)
	bytestring = append(bytestring, g1Aff.FromJacobian(a2).Marshal()...)

	hash := sha512.New()
	hash.Write(bytestring)
	bs := hash.Sum(nil)
	return e.SetBytes(bs).ToBigIntRegular(big.NewInt(0))
}

// ScalarReduce reduces a 512 hash output into a scalar
// func ScalarReduce(data []byte) *ed25519.Scalar {
// 	return ed25519.NewScalar().SetUniformBytes(data)
// }

// ProveShareCorrectnessBatch uses a batched challenge
// func ProveShareCorrectnessBatch(shares Scalars, commits, encEvals Points, pubKeys Points) NizkProofs {
// 	n := len(shares)
// 	if n != len(commits) || n != len(pubKeys) || n != len(encEvals) {
// 		panic("Lengths not equal!")
// 	}

// 	var (
// 		gArray Points
// 		proofs NizkProofs
// 	)
// 	for j := 0; j < n; j++ {
// 		gArray = append(gArray, G)
// 	}
// 	// computing the nizk challenge
// 	chal, responses := DleqBatchProve(gArray, pubKeys, commits, encEvals, shares)
// 	// initializing proofs
// 	for j := 0; j < n; j++ {
// 		proofs = append(proofs, NizkProof{
// 			Commit:   commits[j],
// 			EncEval:  encEvals[j],
// 			Chal:     chal,
// 			Response: responses[j],
// 		})
// 	}
// 	return proofs
// }

// DleqBatchProve computes the challenges using the entire batch
// func DleqBatchProve(g []ed25519.Point, h []ed25519.Point, x []ed25519.Point, y []ed25519.Point, alpha Scalars) (ed25519.Scalar, Scalars) {
// 	n := len(g)
// 	if n != len(x) || n != len(h) || n != len(y) || n != len(alpha) {
// 		panic("Lenghts are not equal!")
// 	}
// 	var w Scalars // w random element  from Zq
// 	for i := 0; i < n; i++ {
// 		w = append(w, ed25519.Random())
// 	}
// 	var a1 Points // a1 = g^w
// 	for i := 0; i < n; i++ {
// 		a1 = append(a1, g[i].Mul(w[i]))
// 	}
// 	var a2 Points // a2 = h^w
// 	for i := 0; i < n; i++ {
// 		a2 = append(a2, h[i].Mul(w[i]))
// 	}
// 	e := DleqDeriveBatchChal(x, y, a1, a2) // the challenge e
// 	var z Scalars
// 	for i := 0; i < n; i++ {
// 		z = append(z, w[i].Sub(alpha[i].Mul(e)))
// 	}
// 	return e, z
// }

// VerifyShares verify that the given encrypted shares are computed accoring to the protocol.
// Returns True if the encrypted shares are valid.
// // If this functions returns True, a collaboration of t nodes is able to recover the secret S.
// func VerifyShares(proofs NizkProofs, pubKeys Points, total, ths int) bool {
// 	numProofs := len(proofs)
// 	if numProofs != total {
// 		log.Error("Incorrect nizk proofs")
// 		return false
// 	}
// 	// 1. verify the DLEQ NIZK proof
// 	if !DleqVerify(numProofs, proofs, pubKeys) {
// 		return false
// 	}
// 	// 2. verify the validity of the shares by sampling and testing with a random codeword
// 	codeword := RandomCodeword(total, ths)
// 	var commitments = make([]*ed25519.Point, total)
// 	for i := 0; i < total; i++ {
// 		commitments[i] = ed25519.NewIdentityPoint().Set(&proofs[i].Commit)
// 	}
// 	product := ed25519.NewIdentityPoint().VarTimeMultiScalarMult(codeword, commitments)
// 	return product.Equal(ONE) == 1
// 	// return true
// }
// func VerifyShares(proofs NizkProofsMixed, pubKeys G1Points, total, ths int) bool {
// 	numProofs := len(proofs)
// 	if numProofs != total {
// 		log.Error("Incorrect nizk proofs")
// 		return false
// 	}
// 	// 1. verify the DLEQ NIZK proof
// 	if !DleqVerifyMixed(numProofs, proofs, pubKeys) {
// 		return false
// 	}
// 	// 2. verify the validity of the shares by sampling and testing with a random codeword
// 	commitments := make([]bls381.G2Affine, total)
// 	for i := 0; i < total; i++ {
// 		commitments[i].Set(&proofs[i].Commit)
// 	}
// 	var product bls381.G2Jac
// 	product.MultiExp(commitments, RANDCODE)
// 	return product.Equal(ONE)
// }

// AggregateCommit aggregates polynomial commitment
func AggregateCommit(total int, indexSets []int, data []*NodeData) *NodeData {
	var (
		commits  = make(G2Points, total)
		encEvals = make(G1Points, total)
		i        int
		proof    NizkProofMixed
		nData    *NodeData
	)
	lenIS := len(indexSets)
	nDataZero := data[0]
	proofs := nDataZero.Proofs
	for i, proof = range proofs {
		commits[i] = proof.Commit
		encEvals[i] = proof.EncEval
	}
	uindexsets := make([]uint64, lenIS)
	if lenIS > 0 {
		for t := 0; t < lenIS; t++ {
			uindexsets[t] = uint64(indexSets[t])
		}
	} else {
		uindexsets = []uint64{}
	}
	for id := 1; id < lenIS; id++ {
		nData = data[id]
		proofs = nData.Proofs
		for i, proof = range proofs {
			commits[i].AddAssign(&proof.Commit)
			encEvals[i].AddAssign(&proof.EncEval)
		}
	}

	root := AggrHash(uindexsets, commits, encEvals) // compute hash of "indexSets|commits|encEvals"
	return &NodeData{
		Root:     root,
		Points:   commits,
		EncEvals: encEvals,
	}
}

// sanityNodeData checks basic structure of a polynomial commitment
func sanityNodeData(aggr bool, com *NodeData, total, ths int) bool {
	// Check for existence of Merkle root
	if aggr && com.Root == (common.Hash{}) {
		return false
	}
	// length of the aggregate
	commitLen := len(com.Points)
	encLen := len(com.EncEvals)
	proofLen := len(com.Proofs)
	if aggr {
		proofLen = commitLen
	}
	log.Debug("Sanity check", "aggr", aggr, "cl", commitLen, "el", encLen, "pl", proofLen)
	if (commitLen != encLen) || (proofLen != encLen) || (encLen != total) {
		return false
	}
	return true
}

// sanityRoundData performs basic checks about RoundData
func sanityRoundData(rdata *RoundData, smrRoot common.Hash, ths int) bool {
	if smrRoot != rdata.Root {
		return false
	}
	if len(rdata.IndexSet) < ths {
		return false
	}
	return true
}

// validatePCommit validates the polynomial commitment using a random codeword
func validatePCommit(commitments G2Points, numNodes, threshold int) bool {
	var (
		lcoms   = make([]bls381.G2Affine, numNodes)
		product bls381.G2Jac
	)
	for i := 0; i < numNodes; i++ {
		lcoms[i] = *new(bls381.G2Affine).FromJacobian(&commitments[i])
	}
	product.MultiExp(lcoms, RANDCODE)
	return product.Equal(ONE)
}

// AggrHash computes the hash of the aggregate data
func AggrHash(isets []uint64, commits G2Points, encEvals G1Points) common.Hash {
	var (
		bytestring []byte
		g1Aff      bls381.G1Affine
		g2Aff      bls381.G2Affine
		tempByte48 [48]byte
		tempByte96 [96]byte
	)

	for _, idx := range isets {
		bs := make([]byte, 4)
		binary.LittleEndian.PutUint32(bs, uint32(idx))
		bytestring = append(bytestring, bs...)
	}
	for _, enc := range encEvals {
		tempByte48 = g1Aff.FromJacobian(&enc).Bytes()
		bytestring = append(bytestring, tempByte48[:]...)
	}
	for _, com := range commits {
		tempByte96 = g2Aff.FromJacobian(&com).Bytes()
		bytestring = append(bytestring, tempByte96[:]...)
	}

	hash := sha512.New()
	hash.Write(bytestring)
	bs := hash.Sum(nil)
	return common.BytesToHash(bs)
}

// ValidateCommit checks for correctness of a aggregated message
func ValidateCommit(aggr bool, com *NodeData, pubKeys G1Points, total, ths int) error {
	// check basic sanity such as length
	if !sanityNodeData(aggr, com, total, ths) {
		return errInvalidSanityCheck
	}
	// check for validity of polynomial commitments
	if !validatePCommit(com.Points, total, ths) {
		return errInvalidPolyCommit
	}
	// check for validity of the NIZK proofs
	if !aggr && !DleqVerifyMixed(total, com.Proofs, pubKeys) {
		return errInvalidNIZK
	}
	return nil
}

// ValidateReconstruct whether a received reconstruction message is valid or not
// func ValidateReconstruct(pkey, encshare, share ed25519.Point, proof NizkProof) bool {
// 	// Using values from the output of the SMR
// 	temp11 := ed25519.NewIdentityPoint().ScalarMult(&proof.Chal, &pkey)
// 	temp12 := ed25519.NewIdentityPoint().ScalarMult(&proof.Response, H)
// 	a1 := temp11.Add(temp11, temp12)

// 	temp21 := ed25519.NewIdentityPoint().ScalarMult(&proof.Chal, &encshare)
// 	temp22 := ed25519.NewIdentityPoint().ScalarMult(&proof.Response, &share)
// 	a2 := temp21.Add(temp21, temp22)

// 	eLocal := DleqDeriveChal(pkey, encshare, *a1, *a2)
// 	if eLocal.Equal(&proof.Chal) == 1 {
// 		return true
// 	}
// 	return false
// }

// ValidateReconstruct whether a received reconstruction message is valid or not
func ValidateReconstruct(pkey, encshare, share *bls381.G1Jac, comm *bls381.G2Jac) bool {
	// var (
	// 	temp11 bls381.G1Jac
	// 	a1     bls381.G1Jac
	// 	temp21 bls381.G1Jac
	// 	a2     bls381.G1Jac
	// )
	// // Using values from the output of the SMR
	// temp11.ScalarMultiplication(pkey, proof.Chal)
	// a1.ScalarMultiplication(H, proof.Response)
	// a1.AddAssign(&temp11)

	// temp21.ScalarMultiplication(encshare, proof.Chal)
	// a2.ScalarMultiplication(share, proof.Response)
	// a2.AddAssign(&temp21)

	// eLocal := DleqDeriveChal(pkey, encshare, &a1, &a2)
	// dleqCheck := eLocal.Cmp(proof.Chal) == 0
	e1, _ := bls381.Pair([]bls381.G1Affine{*new(bls381.G1Affine).FromJacobian(share)}, []bls381.G2Affine{affineG})
	E1, _ := bls381.Pair([]bls381.G1Affine{affineH}, []bls381.G2Affine{*new(bls381.G2Affine).FromJacobian(comm)})
	pairCheck := e1.Equal(&E1)
	return pairCheck
}

// ValidatePrivData validates the private data sent by the leaer
// TODO(@sourav): implement this function
func ValidatePrivData(rData RoundData, root common.Hash) error {
	return nil
}

// ValidateRoundData validates private messages received from leader
func ValidateRoundData(rData RoundData, root common.Hash) bool {
	return true
}

// VerifySecret does the following:
// 1. Obtain v_0 via Langrange interpolation from v_1, ..., v_t, or from any
//  other t-sized subset of {v_1, ..., v_n}. This is possible as the commitments
// 	v_1, ... v_n are all public information after the secret has been shared.
// 2. Use the fact v_0 = g^p(0) = g^s to verify that the given secret s is valid.
// func VerifySecret(secret ed25519.Scalar, commitments []ed25519.Point, threshold int) bool {
// 	v0 := Recover(commitments, threshold)
// 	return v0.Equal(G.Mul(secret))
// }
// func VerifySecret(secret *ed25519.Scalar, commitments Points, threshold int) bool {
// 	v0 := Recover(commitments, threshold)
// 	// return v0.Equal(G.Mul(secret))
// 	return v0.Equal(ed25519.NewGeneratorPoint().ScalarMult(secret, G)) == 1
// }

// Recover takes EXACTLY t (idx, share) tuples and performs Langrange interpolation
// to recover the secret S. The validity of the decrypted shares has to be verified
// prior to a call of this function.
// func Recover(shares Points, threshold int) ed25519.Point {
// 	var idxs Scalars
// 	for i := 1; i <= threshold; i++ {
// 		idxs = append(idxs, ed25519.BintToScalar(*big.NewInt(int64(i))))
// 	}

// 	// rec := ed25519.B // initialing it, will be subtracted later

// 	var LagrangeCoefficients []ed25519.Scalar
// 	var Shares []ed25519.Point
// 	for idx := 0; idx < threshold; idx++ {
// 		// t := LagrangeCoefficientScalar(ed25519.BintToScalar(*big.NewInt(int64(idx + 1))), idxs)
// 		// a := shares[idx].Mul(t)
// 		// rec = rec.Add(a)
// 		LagrangeCoefficients = append(LagrangeCoefficients, LagrangeCoefficientScalar(BintToScalar(*big.NewInt(int64(idx + 1))), idxs))
// 		Shares = append(Shares, shares[idx])
// 	}
// 	rec := ed25519.MSM(LagrangeCoefficients, Shares)
// 	return rec
// }

// RecoverBeacon computes the beacon output
// TODO(sourav): Optimize this!
// DOUBT: Will number of shares always be equal tp threshold?
func RecoverBeacon(shares map[uint64]bls381.G1Jac, threshold int) bls381.G1Jac {
	// initializing indeces
	idxs := make([]*big.Int, threshold)
	i := 0
	for idx := range shares {
		idxs[i] = new(big.Int).SetUint64(idx + 1)
		i++
	}
	var (
		LagrangeCoefficients = make([]fr.Element, threshold)
		lshares              = make([]bls381.G1Affine, threshold)
	)
	ii := 0
	for idx, point := range shares {
		lc := LagrangeCoefficientScalar(new(big.Int).SetUint64(idx+1), idxs)
		LagrangeCoefficients[ii].Set(&lc)
		lshares[ii].FromJacobian(&point)
		ii++
	}
	return *new(bls381.G1Jac).MultiExp(lshares, LagrangeCoefficients)
}

// RandomCodeword returns a random dual code
func RandomCodeword(numNodes int, threshold int) []fr.Element {
	var (
		codeword  []fr.Element
		vi        fr.Element
		numerator fr.Element
		feval     fr.Element
	)

	f := RandomPoly(numNodes - threshold - 1)
	for i := 1; i <= numNodes; i++ {
		vi.SetBigInt(big.NewInt(1))
		for j := 1; j <= numNodes; j++ {
			if j != i {
				numerator.SetBigInt(new(big.Int).Sub(big.NewInt(int64(i)), big.NewInt(int64(j))))
				vi.Mul(&vi, &numerator)
			}
		}
		vi.Inverse(&vi)
		feval.SetBigInt(f.Eval(i))
		codeword = append(codeword, *(vi.Mul(&vi, &feval)))
	}
	return codeword
}

// LagrangeCoefficientScalar compute lagrange coefficints
// func LagrangeCoefficientScalar(i *ed25519.Scalar, indices []*ed25519.Scalar) *ed25519.Scalar {
// 	numerator := BintToScalar(big.NewInt(1))
// 	denominator := BintToScalar(big.NewInt(1))
// 	for j := 0; j < len(indices); j++ {
// 		idx := indices[j]
// 		if idx.Equal(i) != 1 {
// 			numerator.Multiply(numerator, idx)
// 			denominator.Multiply(denominator, ed25519.NewScalar().Subtract(idx, i))
// 		}
// 	}
// 	return numerator.Multiply(numerator, denominator.Invert(denominator))
// }

// LagrangeCoefficientScalar to compute lagrange coefficients
// TODO(@sourav) compute the denominators of the largrange coefficients only once and store them
// Not entirely sure whether computing inverse a priori is good or not as it requires
// multiplying large numbers
func LagrangeCoefficientScalar(i *big.Int, indices []*big.Int) fr.Element {
	var (
		num  = *new(fr.Element).SetBigInt(big.NewInt(1))
		den  = *new(fr.Element).SetBigInt(big.NewInt(1))
		idx  *big.Int
		temp fr.Element
	)
	iLen := len(indices)
	for j := 0; j < iLen; j++ {
		idx = indices[j]
		if idx.Cmp(i) != 0 {
			num.Mul(&num, temp.SetBigInt(idx))
			den.Mul(&den, temp.SetBigInt(new(big.Int).Sub(idx, i)))
		}
	}
	lc := num.Mul(&num, new(fr.Element).Inverse(&den))
	return *lc
}

// func LagrangeCoefficientScalar(i int, indices []int) fr.Element {
// 	var (
// 		num  = *new(fr.Element).SetBigInt(big.NewInt(1))
// 		den  = *new(fr.Element).SetBigInt(big.NewInt(1))
// 		idx  int
// 		temp fr.Element
// 	)
// 	iLen := len(indices)
// 	for j := 0; j < iLen; j++ {
// 		idx = indices[j]
// 		if idx != i {
// 			num.Mul(&num, temp.SetBigInt(big.NewInt(int64(idx))))
// 			den.Mul(&den, temp.SetBigInt(big.NewInt(int64(idx-i))))
// 			temp = lagInverse[idx-i]
// 			den.Mul(&den, &temp)
// 		}
// 	}
// 	lc := num.Mul(&num, &den)
// 	return *lc
// }
