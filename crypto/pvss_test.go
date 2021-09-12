package crypto

import (

	// // "errors"
	// // "strconv"
	// // "bytes"
	// // "unsafe"
	// "crypto/sha512"
	// "crypto/sha256"
	// "ed25519"
	ed25519 "filippo.io/edwards25519"
	"math/big"
	// "reflect"
	"testing"
	// "github.com/ethereum/go-ethereum/crypto/ed25519"
)

var NUM_NODES = 350
var RECOVERY_THRESHOLD = NUM_NODES/3 + 1
var public_keys []ed25519.Point
var secret_keys []ed25519.Scalar
var decrypted_shares []ed25519.Point
var secret *ed25519.Scalar
var encrypted_shares []ed25519.Point
var proofs NizkProofs
var node_data NodeData

func init() {

	for i := 0; i < NUM_NODES; i++ {
		sk, pk := KeyGen()
		secret_keys = append(secret_keys, *sk)
		public_keys = append(public_keys, *pk)
	}
	secret = Random()
	num_receivers := len(public_keys)
	nd := ShareRandomSecret(public_keys, num_receivers, RECOVERY_THRESHOLD, secret)
	encrypted_shares = nd.EncEvals
	proofs = nd.Proofs
	for j := 0; j < len(encrypted_shares); j++ {
		decrypted_shares = append(decrypted_shares, DecryptShare(encrypted_shares[j], secret_keys[j]))
	}
	node_data = nd
}

// a single node generating shares for all other nodes
func BenchmarkShareGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		num_receivers := NUM_NODES
		poly := RandomPoly(RECOVERY_THRESHOLD - 1)
		var shares []ed25519.Scalar
		for i := 1; i <= num_receivers; i++ {
			shares = append(shares, *poly.Eval(i))
		}
	}

}

// time taken to generate commitments
func BenchmarkCommitmentGeneration(b *testing.B) {
	num_receivers := NUM_NODES
	poly := RandomPoly(RECOVERY_THRESHOLD - 1)
	var shares []ed25519.Scalar
	for i := 1; i <= num_receivers; i++ {
		shares = append(shares, *poly.Eval(i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var commitment_shares []ed25519.Point
		for j := 0; j < num_receivers; j++ {
			commitment_shares = append(commitment_shares, *ed25519.NewIdentityPoint().ScalarMult(&shares[j], &G))
		}
	}

}

// time taken to genertae proofs
func BenchmarkProofGeneration(b *testing.B) {
	num_receivers := NUM_NODES
	poly := RandomPoly(RECOVERY_THRESHOLD - 1)
	var shares []ed25519.Scalar
	for i := 1; i <= num_receivers; i++ {
		shares = append(shares, *poly.Eval(i))
	}
	var encrypted_shares []ed25519.Point
	for j := 0; j < num_receivers; j++ {
		encrypted_shares = append(encrypted_shares, *ed25519.NewIdentityPoint().ScalarMult(&shares[j], &public_keys[j]))
	}
	var commitments []ed25519.Point
	for j := 0; j < num_receivers; j++ {
		commitments = append(commitments, *ed25519.NewIdentityPoint().ScalarMult(&shares[j], &G))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ProveShareCorrectness(shares, commitments, encrypted_shares, public_keys)
	}

}

// time taken for aggregation
func BenchmarkAggregation(b *testing.B) {
	num_receivers := NUM_NODES
	poly := RandomPoly(RECOVERY_THRESHOLD - 1)
	var shares []ed25519.Scalar
	for i := 1; i <= num_receivers; i++ {
		shares = append(shares, *poly.Eval(i))
	}
	var encrypted_shares []ed25519.Point
	for j := 0; j < num_receivers; j++ {
		encrypted_shares = append(encrypted_shares, *ed25519.NewIdentityPoint().ScalarMult(&shares[j], &public_keys[j]))
	}
	var commitments []ed25519.Point
	for j := 0; j < num_receivers; j++ {
		commitments = append(commitments, *ed25519.NewIdentityPoint().ScalarMult(&shares[j], &G))
	}

	proofs := ProveShareCorrectness(shares, commitments, encrypted_shares, public_keys)
	nodeData := NodeData{
		Points:   commitments,
		EncEvals: encrypted_shares,
		Proofs:   proofs,
	}
	var idxSets []int
	var nodesData []*NodeData
	for i := 0; i < RECOVERY_THRESHOLD; i++ {
		idxSets = append(idxSets, i+1)
		nodesData = append(nodesData, &nodeData)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AggregateCommit(len(proofs), idxSets, nodesData)
	}

}

// time taken for reedsolomon codeword verification
func BenchmarkCodeWordVerification(b *testing.B) {
	codeword := RandomCodeword(NUM_NODES, RECOVERY_THRESHOLD)
	num_receivers := NUM_NODES
	poly := RandomPoly(RECOVERY_THRESHOLD - 1)
	var shares []ed25519.Scalar
	for i := 1; i <= num_receivers; i++ {
		shares = append(shares, *poly.Eval(i))
	}
	var encrypted_shares []ed25519.Point
	for j := 0; j < num_receivers; j++ {
		encrypted_shares = append(encrypted_shares, *ed25519.NewIdentityPoint().ScalarMult(&shares[j], &public_keys[j]))
	}
	var commitments []*ed25519.Point
	for j := 0; j < num_receivers; j++ {
		commitments = append(commitments, ed25519.NewIdentityPoint().ScalarMult(&shares[j], &G))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// codeword := Cdword()
		// product := commitments[0].Mul(codeword[0])
		// // fmt.Println(len(codeword))
		// // fmt.Println(len(commitments))
		// for i := 1; i < NUM_NODES; i++ {
		// 	product = product.Add(commitments[i].Mul(codeword[i]))
		// }

		_ = ed25519.NewIdentityPoint().VarTimeMultiScalarMult(codeword, commitments)
	}

}

// time taken for nizk proof verification
func BenchmarkShareProofVerification(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if !(DleqVerify(len(public_keys), proofs, public_keys)) {
			b.Errorf("Share verification failed")

		}
	}
}

//benchmarks prove and verify DLEQ
func BenchmarkDLEQ(b *testing.B) {

	for i := 0; i < b.N; i++ {
		alpha := Random()
		e, z := DleqProve(G, *H, *ed25519.NewIdentityPoint().ScalarMult(alpha, &G), *ed25519.NewIdentityPoint().ScalarMult(alpha, H), *alpha)
		proof := NizkProof{
			Commit:   *ed25519.NewIdentityPoint().ScalarMult(alpha, &G),
			EncEval:  *ed25519.NewIdentityPoint().ScalarMult(alpha, H),
			Chal:     e,
			Response: z,
		}
		result := DleqVerify(1, []NizkProof{proof}, []ed25519.Point{*H})
		if !result {
			b.Errorf("DLEQ not working")
		}

	}
}

// bechmarks BeaconRecovery
func Benchmark_recover_secret(b *testing.B) {
	DecSharesMap := make(map[uint64]*ed25519.Point)
	for idx := 0; idx < RECOVERY_THRESHOLD; idx++ {
		DecSharesMap[uint64(idx)] = &decrypted_shares[idx]
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs := RecoverBeacon(DecSharesMap, RECOVERY_THRESHOLD)
		if rs.Equal(ed25519.NewIdentityPoint().ScalarMult(secret, H)) == 0 {
			b.Errorf("Recover secret not working")
		}

	}
}

func TestDLEQ(t *testing.T) {
	alpha := Random()
	e, z := DleqProve(G, *H, *ed25519.NewIdentityPoint().ScalarMult(alpha, &G), *ed25519.NewIdentityPoint().ScalarMult(alpha, H), *alpha)
	proof := NizkProof{
		Commit:   *ed25519.NewIdentityPoint().ScalarMult(alpha, &G),
		EncEval:  *ed25519.NewIdentityPoint().ScalarMult(alpha, H),
		Chal:     e,
		Response: z,
	}
	result := DleqVerify(1, []NizkProof{proof}, []ed25519.Point{*H})
	if !result {
		t.Errorf("DLEQ not working")
	}

}

// func TestDLEQInvalidChallenge(t *testing.T) {
// 	alpha := ed25519.Random()
// 	e, z := DLEQ_prove([]ed25519.Point{G}, []ed25519.Point{H}, []ed25519.Point{G.Mul(alpha)}, []ed25519.Point{H.Mul(alpha)}, []ed25519.Scalar{alpha})
// 	e = e.Add(ed25519.BintToScalar(*big.NewInt(1)))

// 	result := DLEQ_verify([]ed25519.Point{G}, []ed25519.Point{H}, []ed25519.Point{G.Mul(alpha)}, []ed25519.Point{H.Mul(alpha)}, e, z)
// 	if result {
// 		t.Errorf("DLEQ(IC) not working")
// 	}

// }

func TestDLEQInvalidChallenge(t *testing.T) {
	alpha := Random()
	e, z := DleqProve(G, *H, *ed25519.NewIdentityPoint().ScalarMult(alpha, &G), *ed25519.NewIdentityPoint().ScalarMult(alpha, H), *alpha)
	e = *ed25519.NewScalar().Add(&e, BintToScalar(big.NewInt(1)))
	proof := NizkProof{
		Commit:   *ed25519.NewIdentityPoint().ScalarMult(alpha, &G),
		EncEval:  *ed25519.NewIdentityPoint().ScalarMult(alpha, H),
		Chal:     e,
		Response: z,
	}
	result := DleqVerify(1, []NizkProof{proof}, []ed25519.Point{*H})
	if result {
		t.Errorf("DLEQ not working")
	}

}

// func TestDLEQNonEqual(t *testing.T) {
// 	alpha := ed25519.Random()
// 	beta := ed25519.Random()
// 	e, z := DLEQ_prove([]ed25519.Point{G}, []ed25519.Point{H}, []ed25519.Point{G.Mul(alpha)}, []ed25519.Point{H.Mul(beta)}, []ed25519.Scalar{alpha})
// 	e = e.Add(ed25519.BintToScalar(*big.NewInt(1)))

// 	result := DLEQ_verify([]ed25519.Point{G}, []ed25519.Point{H}, []ed25519.Point{G.Mul(alpha)}, []ed25519.Point{H.Mul(beta)}, e, z)
// 	if result {
// 		t.Errorf("DLEQ(NE) not working")
// 	}

// }

func TestVerification(t *testing.T) {
	for i := 0; i < len(encrypted_shares); i++ {
		enc_share := encrypted_shares[i]
		sk := secret_keys[i]
		pk := public_keys[i]
		// dec_share := DecryptShare(enc_share, sk)
		// chal,res := DleqProve(*H,dec_share,pk,enc_share,sk)
		// proof := NizkProof{
		// 	Commit: pk,
		// 	EncEval: enc_share,
		// 	Chal: chal,
		// 	Response: res,
		// }

		// TODO:Remove first parameter from ReconstructData in pvss.go
		recdata := ReconstructData(G, enc_share, pk, sk)
		// TODO: Changed starting index of for loop in ValidateReconstrcut to i = 0
		if !ValidateReconstruct(pk, enc_share, recdata.DecShare) {
			t.Errorf("Share encryption proof not working")
		}

	}

}

// func BenchmarkVerification(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		for i := 0; i < len(encrypted_shares); i++ {
// 			enc_share := encrypted_shares[i]
// 			sk := secret_keys[i]
// 			pk := public_keys[i]
// 			dec_share := Decrypt_share(enc_share, sk)
// 			proof_new := Prove_share_decryption(dec_share, enc_share, sk, pk)
// 			if !Verify_decrypted_share(dec_share, enc_share, pk, proof_new) {
// 				b.Errorf("Share encryption proof not working")
// 			}

// 		}
// 	}

//  }

func TestShareVerification(t *testing.T) {
	if !(VerifyShares(proofs, public_keys, len(public_keys), RECOVERY_THRESHOLD)) {
		t.Errorf("Share verification failed")

	}
}

// // func BenchmarkShareVerification(b *testing.B) {
// // 	for i := 0; i < b.N; i++ {
// // 		if !(Verify_shares(encrypted_shares, proof, public_keys, RECOVERY_THRESHOLD)) {
// // 			b.Errorf("Share verification failed")

// // 		}
// // 	}
// // }

// func Test_verify_secret(t *testing.T) {
// 	cmts := proof.commitments
// 	if !Verify_secret(secret, cmts, RECOVERY_THRESHOLD) {
// 		t.Errorf("Verify secret not working")
// 	}
// }

// // func Benchmark_verify_secret(b *testing.B) {
// // 	for i := 0; i < b.N; i++ {
// // 		cmts := proof.commitments
// // 		if !Verify_secret(secret, cmts, RECOVERY_THRESHOLD) {
// // 			b.Errorf("Verify secret not working")
// // 		}
// // 	}
// // }

func Test_recover_secret(t *testing.T) {
	DecSharesMap := make(map[uint64]*ed25519.Point)
	for idx := 0; idx < RECOVERY_THRESHOLD; idx++ {
		DecSharesMap[uint64(idx)] = &decrypted_shares[idx]
	}

	rs := RecoverBeacon(DecSharesMap, RECOVERY_THRESHOLD)
	if rs.Equal(ed25519.NewIdentityPoint().ScalarMult(secret, H)) == 0 {
		t.Errorf("Recover secret not working")
	}
}

// func TestPoint_G(t *testing.T) {
// 	if !reflect.DeepEqual(H, H) {
// 		t.Errorf("Equality test not working")
// 	}
// }
