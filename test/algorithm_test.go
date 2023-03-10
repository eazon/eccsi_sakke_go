/* Desp:
 */

package test

import (
	"eccsi_sakke_go/consts"
	"eccsi_sakke_go/crypto"
	"flag"
	"fmt"
	slog "github.com/golang/glog"
	"math"
	"math/big"
	//"tokms"
	//"sdk/slog"
	"testing"
)

func Test_Sakke_PointExponent(t *testing.T) {
	flag.Set("alsologtostderr", "true")
	p_tmp_bn, _ := new(big.Int).SetString("2", 10)

	g, _ := new(big.Int).SetString("2", 10)
	r_bn, _ := new(big.Int).SetString("10", 10)

	result_x_bn, result_y_bn := new(big.Int), new(big.Int)

	slog.Infof("p_tmp_bn %v", p_tmp_bn)
	slog.Infof("result_x_bn %v", result_x_bn)
	slog.Infof("result_y_bn %v", result_y_bn)
	slog.Infof("One %v", crypto.One)
	slog.Infof("g %v", g)
	slog.Infof("r_bn %v", r_bn)

	crypto.SakkePointExponent(p_tmp_bn, result_x_bn, result_y_bn, crypto.One, g, r_bn)

	slog.Infof("p_tmp_bn %v", p_tmp_bn)
	slog.Infof("result_x_bn %v", result_x_bn)
	slog.Infof("result_y_bn %v", result_y_bn)
	slog.Infof("One %v", crypto.One)
	slog.Infof("g %v", g)
	slog.Infof("r_bn %v", r_bn)

	//slog.Infof("p_tmp_bn %+v", g.Exp(g, r_bn, nil))
	//
	//two_to_power_n_bn := new(big.Int).SetBit(&zero, 0, 1)
	//slog.Infof("p_tmp_bn %+v", two_to_power_n_bn)

}

const (
	R = "13EE3E1B8DAC5DB168B1CEB32F0566A4C273693F78BAFFA2A2EE6A686E6BD90F8206CCAB84E7F42ED39BD4FB131012ECCA2ECD2119414560C17CAB46B956A80F58A3302EB3E2C9A228FBA7ED34D8ACA2392DA1FFB0B17B2320AE09AAEDFD0235F6FE0EB65337A63F9CC97728B8E5AD0460FADE144369AA5B2166213247712096"
)

func Test_g_power_rn(t *testing.T) {
	crypto.InitSakkeAndEccsi()
	r, _ := new(big.Int).SetString(R, 16)
	g_power_rn := new(big.Int).Exp(crypto.SakkeEC.Param_g, r, crypto.SakkeEC.Param_p)
	slog.Infof("g_power_rn %s", g_power_rn.Text(16))

	// todo-yyl: 在g与r一致的情况下， 如下计算方式 与 rfc文档中计算结果得到的一致
	p_tmp_bn := new(big.Int).Set(crypto.SakkeEC.Param_p)
	result_x_bn, result_y_bn := new(big.Int), new(big.Int)
	crypto.SakkePointExponent(p_tmp_bn, result_x_bn, result_y_bn, crypto.One, crypto.SakkeEC.Param_g, r)
	g_to_power_r_bn := new(big.Int).Mod(result_x_bn, p_tmp_bn)
	g_to_power_r_bn.ModInverse(g_to_power_r_bn, p_tmp_bn)
	g_to_power_r_bn.Mul(g_to_power_r_bn, result_y_bn)
	g_to_power_r_bn.Mod(g_to_power_r_bn, p_tmp_bn)
	slog.Infof("g_to_power_r_bn %s", g_to_power_r_bn.Text(16))
}

// Elements of F_p MUST be represented as integers in the range 0 to p-1 using the octet string representation defined above.
// Such octet strings MUST have length L = Ceiling(lg(p)/8)
func Test_Ceiling_lg_div8(t *testing.T) {
	crypto.InitSakkeAndEccsi()
	var zero big.Int
	two := new(big.Int).SetUint64(2)
	slog.Infof("bit length of two = %d", two.BitLen())

	// lg(p)
	res := 0
	p := new(big.Int).Set(crypto.SakkeEC.Param_p)
	for {
		p = p.Div(p, two)
		if 0 == p.Cmp(&zero) {
			break
		}
		res++
	}
	slog.Infof("res= %d", res)
	// L = Ceiling(res(p)/8)
	L := int(math.Ceil(float64(res) / 8))
	slog.Infof("L= %d", L)

	//1. 右移3位 等价 除以8
	//2. +7 等价 向上取整
	//3. log2 用于得到 该数值的2的指数
	L = (crypto.SakkeEC.Param_p.BitLen() + 7) >> 3 // 2^3 = 8  因此 右移位数等于 8的2的指数，即 右移3位 等价于 除以8
	slog.Infof("L= %d", L)

	// 38 D = 100110 B  bit长度反应了2的指数情况
	tmp := new(big.Int).SetUint64(38)
	slog.Infof("bit length = %d", tmp.BitLen())

}

func Test_add(t *testing.T) {
	fmt.Println(1 + 2)
}

// l = ceiling(lg(n)/hashlen)
func Test_Ceiling_lg_divX(t *testing.T) {
	// 算法#1
	l := (crypto.SakkeEC.Param_p.BitLen() + 255) >> 8 // 2^8 = 256  因此 右移位数等于 256的2的指数，即 右移8位 等价于 除以256
	slog.Infof("l= %d", l)

	// 算法#2
	l = Ceiling(lg(crypto.SakkeEC.Param_p), 256)
	slog.Infof("l= %d", l)
}

func Ceiling(x, y int) int {
	res := int(math.Ceil(float64(x) / float64(y)))
	return res
}

// lg(x): The base 2 logarithm of the real value x
func lg(value *big.Int) int {
	var zero big.Int
	two := new(big.Int).SetUint64(2)
	res := 0
	p := new(big.Int).Set(value)
	for {
		p = p.Div(p, two)
		if 0 == p.Cmp(&zero) {
			break
		}
		res++
	}
	//slog.Infof("res= %d", res)

	return res
}

func Test_GetGMKIDByGUKID(t *testing.T) {
	msUri := "sip:6009755001@mcptt.mcs.com"
	var ptr crypto.SSVKeyInfo
	ptr.SSV = []byte("abcdefg")
	ptr.KeyId = 12345678
	guiId := crypto.GenerateGUKID(&ptr, msUri)
	GmkId1 := crypto.GetGMKIDByGUKID(ptr.SSV, guiId, msUri)
	slog.Infof("GmkId1: %v", GmkId1)
}

// 数据来源：mcc call seat
func Test_GenerateKeySalt(t *testing.T) {
	ssv := []byte{45, 193, 240, 138, 162, 39, 41, 170, 173, 88, 53, 126, 214, 234, 86, 134}
	CSB_Id := [4]byte{30, 46, 227, 64}
	Rand := [16]byte{253, 50, 80, 192, 197, 33, 1, 91, 223, 190, 169, 132, 229, 237, 210, 6}

	//发送key+salt：5b b2 a5 6d e5 6c 91 5e 58 51 dc 3a 77 af f1 2d 55 0c f6 bf c1 00 87 44 68 c7 bb d8
	crypto.GenerateKeySalt(ssv, CSB_Id, consts.CS_ID_Initiator_MCPtt_Private_Call, Rand)

	//接收key+salt：27 f4 33 4c f9 4f a9 9c c9 5d 61 89 a5 9f 29 3e bb c7 2a dc 91 47 b5 fc 80 39 a4 4a
	crypto.GenerateKeySalt(ssv, CSB_Id, consts.CS_ID_Receiver_MCPtt_Private_Call, Rand)
}

// 数据来源：mcc call seat
func Test_GenerateKeySalt1(t *testing.T) {
	// invitiator masterkey：8e b0 64 da 4d b6 60 73 58 df c4 28 5d f6 62 6e 78 5d 0a 61 bd 21 0e eb 3e f8 a8 14
	// receiver masterkey:2d 67 12 f1 46 68 2f b7 37 27 31 d8 0b 86 bb 88 e2 37 75 52 88 bc 57 0a fc 87 ab cc
	ssv := []byte{110, 149, 208, 192, 252, 202, 1, 122, 213, 162, 60, 72, 165, 84, 255, 99}
	CSB_Id := [4]byte{16, 139, 98, 82}
	Rand := [16]byte{238,184,35,170,90,40,33,209,142,26,117,115,210,68,214,49}

	//发送key+salt：5b b2 a5 6d e5 6c 91 5e 58 51 dc 3a 77 af f1 2d 55 0c f6 bf c1 00 87 44 68 c7 bb d8
	crypto.GenerateKeySalt(ssv, CSB_Id, consts.CS_ID_Initiator_MCPtt_Private_Call, Rand)

	//接收key+salt：27 f4 33 4c f9 4f a9 9c c9 5d 61 89 a5 9f 29 3e bb c7 2a dc 91 47 b5 fc 80 39 a4 4a
	crypto.GenerateKeySalt(ssv, CSB_Id, consts.CS_ID_Receiver_MCPtt_Private_Call, Rand)
}

// 数据来源：mcc call seat
func Test_ParseImessageData(t *testing.T) {
	var iMsg crypto.IMessage
	mikeyStr := "ARoFARLHpywAAQsA6Pgd+gAAAAAOEHoFBS69AtaCHlo5cV7QgJEOAQEAFnNpcDo1MDAxQG1jcHR0Lm1jcy5jb20OAgEAGHNpcDo1NTUwMDJAbWNwdHQubWNzLmNvbQ4GAQAPa21zLmV4YW1wbGUub3JnCgcBAA9rbXMuZXhhbXBsZS5vcmcaAQAAEgABBgEBIAQBDAUBAAYBABQBEAQBAgEhBAla5e0k2wk8DRcAbyF9e5SfwJNHuU4f5yDA3MH34RvSMvBn9jzGLR4FFWje6x1FzeV0hQqHJ2yDqIxb8Orb2YPY2MS1sOgwhXqfgpGvre48t3wa6ajnX02PwOgPyJY/qi/T7Bzo9shEoNQkX9W2MoWtN1ObP5B/JAjk1DkwCdw+Ro+dBR7920gWzfXHgDksurSvRQVzMS4w9G6xDiE7hS8UCGIdWQh7qfpdia3pVUki8wQzGwYYY9Bx9oKc2CMNfwjvpzYEQGXqX4cghxdmoWj39KtgVEP3N9vVQ9XbyXqYxJlAQHNzjekmXgJWUOADxJM44iUEtcHHCCY9YqwM6d4U8epEsZTBO9W5HpH4EPBti+vlbML+jkNIkJzt37m+tCCB/+NuEP3M/rTNCak7pnboYBuTrRV+F0JnmsVDU8EBJQs9wwwvyG6uCdjzvVLQlSklHKKNuV+mVqjGzj3+PdyLFgRBpt5dCdd2tzXxmlaeiDohzOy9R3teDbZJSU9477MtG44LOJqgSlPXUPRrQ0w2gb5uwC4kUnYqH4Xq6DiJTzKH"
	crypto.ParseImessageData(mikeyStr, &iMsg)
}