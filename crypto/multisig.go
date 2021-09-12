package crypto

import (
	// "github.com/consensys/gurvy/bn256"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	// "reflect"
	"bytes"
)

func bigFromBase10(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

var p = bigFromBase10("65000549695646603732796438742359905742825358107623003571877145026864184071783")
var tempG2 = new(bn256.G2).ScalarBaseMult(bigFromBase10("0"))
var tempG1 = new(bn256.G1).ScalarBaseMult(bigFromBase10("0"))

var NumNodes = 4
var MemKeys []*bn256.G1

// var AggPubKey *bn256.G2

// var GROUP_ORDER, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// // Random returns a random scalar
// func Random() *big.Int {
// 	v, _ := rand.Int(rand.Reader, GROUP_ORDER)
// 	// fmt.Println(v.String())
// 	return v
// }
var PublicKeys []*bn256.G2
var SecretKeys []*big.Int

func GroupSetup() {

	for i := 0; i < NumNodes; i++ {
		sk, pk, _ := bn256.RandomG2(rand.Reader)
		PublicKeys = append(PublicKeys, pk)
		SecretKeys = append(SecretKeys, sk)
	}
	apk, exponents := KeyAgg(PublicKeys)
	MemKeys = MemKeySetup(apk, exponents, SecretKeys)

}

func MemKeySetup(apk *bn256.G2, exponents []*big.Int, SecretKeys []*big.Int) []*bn256.G1 {
	// fmt.Println(exponents)
	var MbKeys []*bn256.G1
	for j, _ := range SecretKeys {
		apkbytes := apk.Marshal()
		hashmessage := append(apkbytes, byte(j+1))
		digest := bn256.HashG1(hashmessage, []byte{byte(2)})
		memkey_j := new(bn256.G1).ScalarBaseMult(bigFromBase10("0"))
		for i, sk := range SecretKeys {
			mu_i := new(bn256.G1).ScalarMult(digest, new(big.Int).Mul(sk, exponents[i]))
			// fmt.Println(mu_i)
			memkey_j.Add(memkey_j, mu_i)
		}
		p1 := bn256.Pair(memkey_j, new(bn256.G2).ScalarBaseMult(bigFromBase10("1"))).Marshal()
		p2 := bn256.Pair(digest, apk).Marshal()
		if !bytes.Equal(p1, p2) {
			// fmt.Println("Membership Key Setup failed")
		}
		MbKeys = append(MbKeys, memkey_j)
	}
	return MbKeys
}

// func KeyGen() (*big.Int,*bn256.G2){
// 	sk,pk,_:= bn256.RandomG2(rand.Reader)

// 	return sk,pk
// }

func KeyAgg(pklist []*bn256.G2) (*bn256.G2, []*big.Int) {
	var pklistbytes []byte
	var exponents []*big.Int
	for _, pk := range pklist {
		pklistbytes = append(pklistbytes, pk.Marshal()...)
	}
	// apk := new(bn256.G2).ScalarBaseMult(bigFromBase10("0"))
	apk := new(bn256.G2).ScalarBaseMult(bigFromBase10("0"))
	// var apk *bn256.G2
	// g2temp :=new(bn256.G2).ScalarBaseMult(bigFromBase10("0"))
	for _, pk := range pklist {
		hashmessage := pk.Marshal()
		hashmessage = append(hashmessage, pklistbytes...)
		hash256 := sha256.New()
		hash256.Write(hashmessage)
		exponent := new(big.Int).Mod(new(big.Int).SetBytes(hash256.Sum(nil)), bn256.Order)
		term := new(bn256.G2).ScalarMult(pk, exponent)
		// temp := new(bn256.G2).ScalarMult(tempG2,new(big.Int).Mul(SecretKeys[i],exponent))

		apk.Add(apk, term)
		exponents = append(exponents, exponent)
	}
	// fmt.Println(apk)

	// apk = new(bn256.G2).Add(apk,new(bn256.G2).Neg(new(bn256.G2)))
	// fmt.Println(exponents)
	return apk, exponents
}

func BlsSign(pkaggbytes []byte, sk *big.Int, memkey *bn256.G1, message []byte) *bn256.G1 {
	// DoneTODO(@vinith): Do one time setups only once and store it
	// somewhere.
	// apk, _ := KeyAgg(pklist)
	apkbytes := pkaggbytes
	// TODO(@vinith), low priority:
	// Check if existing library already does that.
	hashmessage := append(apkbytes, message...)
	digest := bn256.HashG1(hashmessage, []byte{byte(0)})
	signature := new(bn256.G1).Add(new(bn256.G1).ScalarMult(digest, sk), memkey)
	return signature
}

func SignAggregator(pklist []*bn256.G2, signlist []*bn256.G1) (*bn256.G2, *bn256.G1) {
	aggpk := new(bn256.G2).ScalarBaseMult(bigFromBase10("0"))
	aggsig := new(bn256.G1).ScalarBaseMult(bigFromBase10("0"))
	for i, _ := range pklist {
		aggpk = new(bn256.G2).Add(aggpk, pklist[i])
		aggsig = new(bn256.G1).Add(aggsig, signlist[i])
	}
	return aggpk, aggsig
}

func Verify(nodelist []int, apk *bn256.G2, message []byte, aggpk *bn256.G2, aggsig *bn256.G1) bool {
	// p1
	apkbytes := apk.Marshal()
	hashmessage := append(apkbytes, message...)
	digest := bn256.HashG1(hashmessage, []byte{byte(0)})
	p1 := bn256.Pair(digest, aggpk)

	//p2
	h2dt := new(bn256.G1).ScalarBaseMult(bigFromBase10("0"))
	for _, j := range nodelist {
		apkbytes := apk.Marshal()
		hashmessage := append(apkbytes, byte(j)) // check if j starts from 0
		digest := bn256.HashG1(hashmessage, []byte{byte(2)})
		h2dt = new(bn256.G1).Add(h2dt, digest)
	}
	p2 := bn256.Pair(h2dt, apk)

	// plhs = p1+p2
	plhs := new(bn256.GT).Add(p1, p2).Marshal()
	//prhs
	prhs := bn256.Pair(aggsig, new(bn256.G2).ScalarBaseMult(bigFromBase10("1"))).Marshal()

	if !bytes.Equal(plhs, prhs) {
		// fmt.Println("Signature verification failed")
		// return false
	}
	return true

}



// func main() {
// 	// var pklist [] *bn256.G2
// 	// for i:=0;i<3;i++ {
// 	// 	_,pk := KeyGen()
// 	// 	pklist = append(pklist,pk)
// 	// }
// 	// // fmt.Println(g1,g2)

// 	// fmt.Println(KeyAgg(pklist))
// 	// fmt.Println(new(bn256.G2).ScalarBaseMult(bigFromBase10("0")))
// 	// fmt.Println(new(bn256.G2).ScalarMult(tempG2,bigFromBase10("0")))
// 	// fmt.Println(new(bn256.G2).ScalarMult(tempG2,bigFromBase10("0")))

// 	GroupSetup()
// 	var SignList []*bn256.G1
// 	var pubkeys []*bn256.G2
// 	message := []byte{byte(0)}
// 	for i, sk := range SecretKeys {
// 		SignList = append(SignList, BlsSign(PublicKeys, sk, MemKeys[i], message))
// 		pubkeys = append(pubkeys, PublicKeys[i])
// 		if i == 2 {
// 			break
// 		}
// 	}
// 	AggPk, AggSign := SignAggregator(pubkeys, SignList)
// 	nodelist := []int{1, 2, 4}
// 	apk, _ := KeyAgg(PublicKeys)
// 	fmt.Println(Verify(nodelist, apk, message, AggPk, AggSign))
// 	// fmt.Println(MemKeys)

// 	// sk,pk,_ := bn256.RandomG2(rand.Reader)
// 	// fmt.Println(pk)
// 	// fmt.Println(new(bn256.G2).ScalarMult(tempG2,sk))

// 	// a, _ := rand.Int(rand.Reader, bn256.Order)
// 	// b, _ := rand.Int(rand.Reader, bn256.Order)
// 	// c, _ := rand.Int(rand.Reader, bn256.Order)

// 	// pa, pb, pc := new(bn256.G1), new(bn256.G1), new(bn256.G1)
// 	// qa, qb, qc := new(bn256.G2), new(bn256.G2), new(bn256.G2)

// 	// // pa.Unmarshal(new(bn256.G1).ScalarBaseMult(a).Marshal())
// 	// // qa.Unmarshal(new(bn256.G2).ScalarBaseMult(a).Marshal())
// 	// // pb.Unmarshal(new(bn256.G1).ScalarBaseMult(b).Marshal())
// 	// // qb.Unmarshal(new(bn256.G2).ScalarBaseMult(b).Marshal())
// 	// // pc.Unmarshal(new(bn256.G1).ScalarBaseMult(c).Marshal())
// 	// // qc.Unmarshal(new(bn256.G2).ScalarBaseMult(c).Marshal())

// 	// pa = (new(bn256.G1).ScalarBaseMult(a))
// 	// qa = (new(bn256.G2).ScalarBaseMult(a))
// 	// pb = (new(bn256.G1).ScalarBaseMult(b))
// 	// qb = (new(bn256.G2).ScalarBaseMult(b))
// 	// pc = (new(bn256.G1).ScalarBaseMult(c))
// 	// qc = (new(bn256.G2).ScalarBaseMult(c))

// 	// k1 := bn256.Pair(pb, qc)
// 	// k1.ScalarMult(k1, a)
// 	// k1Bytes := k1.Marshal()

// 	// k2 := bn256.Pair(pc, qa)
// 	// k2.ScalarMult(k2, b)
// 	// k2Bytes := k2.Marshal()

// 	// k3 := bn256.Pair(pa, qb)
// 	// k3.ScalarMult(k3, c)
// 	// k3Bytes := k3.Marshal()

// 	// if !bytes.Equal(k1Bytes, k2Bytes) || !bytes.Equal(k2Bytes, k3Bytes) {
// 	// 	fmt.Println("keys didn't agree")
// 	// }
// }
