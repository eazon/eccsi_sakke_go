/* Desp:
 */

package crypto

import (
	"crypto/rand"
	"eccsi_sakke_go/consts"
	"math/big"
	//"sdk/slog"
	slog "github.com/golang/glog"
)


func MakeSSVKey(enType consts.EncAlgoType, isGroupCall bool) *SSVKeyInfo {
	bits := consts.AES_128_BITS
	if enType == consts.AlgoAes256 {
		bits = consts.AES_256_BITS
	}

	count := 0
	loopTimes := 10
	// a. 生成一个随机大数 m_ssv
	max := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	slog.Infof("max value of %d bits: %v", bits, max)

	SSV, _ := rand.Int(rand.Reader, max)
	for count = 0; count < loopTimes; count++ {
		if 0 != SSV.Cmp(big.NewInt(0)) {
			slog.Infof("[%d] non-zero ssv, break.", count)
			break
		}
		SSV, _ = rand.Int(rand.Reader, max)
	}
	if count == loopTimes {
		slog.Error("make ssv failed, return false.")
		return nil
	}

	// b. 生成一个随机大数，16字节  Rand
	max = new(big.Int).Lsh(big.NewInt(1), 128)
	slog.Infof("max value of 128 bits: %v", max)

	Rand, _ := rand.Int(rand.Reader, max)
	RandBytes := Rand.Bytes()
	for count = 0; count < loopTimes; count++ {
		if 0 != Rand.Cmp(big.NewInt(0)) && 16 == len(RandBytes) {
			slog.Infof("[%d] non-zero and 16Bytes Rand, break.", count)
			break
		}
		Rand, _ = rand.Int(rand.Reader, max)
		RandBytes = Rand.Bytes()
	}
	if count == loopTimes {
		slog.Error("make Rand failed, return false.")
		return nil
	}

	// GMKRand PCKRand
	max = new(big.Int).Lsh(big.NewInt(1), 32)
	slog.Infof("max value of 32 bits: %v", max)

	randNum, _ := rand.Int(rand.Reader, max)
	for count = 0; count < loopTimes; count++ {
		if 0 != randNum.Cmp(big.NewInt(0)) {
			slog.Infof("[%d] non-zero gmkrand, break.", count)
			break
		}
		randNum, _ = rand.Int(rand.Reader, max)
	}
	if count == loopTimes {
		slog.Error("make GMKRand failed, return false.")
		return nil
	}
	slog.Infof("randNum: %v", randNum)

	tmpSSVRand := randNum.Bytes()
	// 处理 tmpSSVRand不足4字节
	tlen := len(tmpSSVRand)
	if tlen < 4 {
		slog.Warning("tmpSSVRand=%v, len[%d] < 4, need to pad.", tmpSSVRand, tlen)
	}
	for i := 0; i < 4-tlen; i++ {
		tmpSSVRand = append(tmpSSVRand, byte(10+i))
	}
	slog.Infof("tmpSSVRand: %v", tmpSSVRand)

	res := &SSVKeyInfo{}
	res.SSVLen = uint32(bits/8)
	//res.SSV = string(EachByteToTwoChar(SSV.Bytes()))
	//res.Rand = string(EachByteToTwoChar(RandBytes))
	//copy(res.SSV, SSV.Bytes())
	//copy(res.Rand, RandBytes)
	res.SSV = SSV.Bytes()
	copy(res.Rand[:], RandBytes)

	res.KeyId = uint32(tmpSSVRand[0] & 0xFF)
	res.KeyId += uint32(tmpSSVRand[1]) << 8
	res.KeyId += uint32(tmpSSVRand[2]) << 16
	res.KeyId += uint32(tmpSSVRand[3]) << 24
	res.KeyId = res.KeyId & 0x0FFFFFFF

	if !isGroupCall { // PCK-ID：长度为32个bits，与GMK-ID类似，由pupose tag(取值为1)与28 bits的随机值组成
		res.KeyId ^= 0x10000000
	}
	slog.Infof("MakeSSVKey enType %v, len_ssv_bytes %v, ssv_bigInt %v, ssv_bytes %v", enType, len(res.SSV), SSV, res.SSV)
	slog.Infof("MakeSSVKey res: %+v", res)
	return res
}