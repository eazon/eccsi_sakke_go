/* Desp: 椭圆曲线加密，初始化加密曲线
 */

package crypto

import (
	"crypto/elliptic"
	"math/big"
	//"sdk/slog"
	slog "github.com/golang/glog"
)

var EccsiEC = &EccsiCurve{}
var SakkeEC = &SakkeCurve{}

//const (
//	SAKKE_XY_LEN = 256		// Sakke X/Y坐标数值的16进制字符串长度	128*2
//	ECCSI_XY_LEN = 64		// Eccsi X/Y坐标数值的16进制字符串长度 32*2
//	SSK_LEN	= 68			// 32*2, 暂取68   todo-yyl: 为什么是 68呢？ 暂不修改吧，这是KMS端决定的
//)

const (
	SAKKE_XY_BYTES = 128		// Sakke X/Y坐标数值的字节数128
	ECCSI_XY_BYTES = 32			// Eccsi X/Y坐标数值的字节数32
	ECCSI_N = 32				// N = Ceiling(n/8)   [RFC6507][4.1. Static Parameters]
)

func InitSakkeAndEccsi() {
	SakkeEC.Init()
	EccsiEC.Init()
}

/*
椭圆曲线方程: y² = x³ + ax + b modulo p

Eccsi签名、Sakke加密各自具有一条椭圆曲线，两者的椭圆曲线方程不同，如下:
Eccsi: y² = x³ - 3x + b modulo p
Sakke: y² = x³ - 3x modulo p, 其中 b等于0

KMS、GMKMS两个服务使用 相同的 Eccsi曲线和Sakke曲线
Tips: elliptic.P256 签名曲线参数 与 18_kms/Main/src/CryptService.cpp和19_mcgmkms/encgmk/GMKGenerate.cpp 定义的签名曲线参数相同;
		因此，Eccsi签名曲线可复用 标准库elliptic.P256
*/

// eccsi签名椭圆曲线
type EccsiCurve struct {
	*elliptic.CurveParams

	/*********************************************************************
	* 字段说明：	协议参数名
	* 参见文档：	[RFC6507][4.1. Static Parameters]
	*********************************************************************/
	Param_p	*big.Int		// 由于Go语法限制增加前缀"Param_"
	Param_B *big.Int
	Param_Gx *big.Int
	Param_Gy *big.Int
	Param_q *big.Int
}

func (eccsi *EccsiCurve)Init() {
	eccsi.CurveParams = elliptic.P256().Params()  // P256参数值详见 p256_asm.go

	eccsi.Param_p = eccsi.P
	eccsi.Param_q = eccsi.N
	eccsi.Param_B = eccsi.B
	eccsi.Param_Gx = eccsi.Gx
	eccsi.Param_Gy = eccsi.Gy
}

// sakke加密椭圆曲线
type SakkeCurve struct {
	*elliptic.CurveParams

	/*********************************************************************
		* 字段说明：	协议参数名
		* 参见文档：	[RFC6508][2.1. Notation]
	   				[RFC6509][Appendix A. Parameters for Use in MIKEY-SAKKE]
		*********************************************************************/
	Param_p	*big.Int	// 由于Go语法限制增加前缀"Param_"
	Param_q *big.Int
	Param_B *big.Int
	Param_Px *big.Int
	Param_Py *big.Int

	Param_g *big.Int
}

func (sakke *SakkeCurve)Init() {
	sakke.CurveParams = &elliptic.CurveParams{Name: "Sakke"}
	sakke.P, _ = new(big.Int).SetString(SAKKE_p, 16)
	sakke.N, _ = new(big.Int).SetString(SAKKE_q, 16)
	sakke.B, _ = new(big.Int).SetString(SAKKE_B, 16)
	sakke.Gx, _ = new(big.Int).SetString(SAKKE_Px, 16)
	sakke.Gy, _ = new(big.Int).SetString(SAKKE_Py, 16)

	slog.Info("the bit size of sakke.P is %d.", sakke.P.BitLen())
	sakke.BitSize = sakke.P.BitLen()	// 参数P的bit位数，见源码注释

	sakke.Param_p = sakke.P
	sakke.Param_q = sakke.N
	sakke.Param_B = sakke.B
	sakke.Param_Px = sakke.Gx
	sakke.Param_Py = sakke.Gy
	sakke.Param_g, _ = new(big.Int).SetString(SAKKE_g, 16)
}

/*
	rfc6507 Appendix A. Test Data
	p:
	FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
	B:
	5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
	q:
	FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
	G:
	046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
	KPAK :
	0450D4670BDE75244F28D2838A0D25558A7A72686D4522D4C8273FB6442AEBFA93DBDD37551AFD263B5DFD617F3960C65A8C298850FF99F20366DCE7D4367217F4
	PVT :
	04758A142779BE89E829E71984CB40EF758CC4AD775FC5B9A3E1C8ED52F6FA36D9A79D247692F4EDA3A6BDAB77D6AA6474A464AE4934663C5265BA7018BA091F79
	SSK :
	23F374AE1F4033F3E9DBDDAAEF20F4CF0B86BBD5A138A5AE9E7E006B34489A0D
 */
func InitEccsi_test() {
	EccsiEC.CurveParams = elliptic.P256().Params()  // P256参数值详见 p256_asm.go

	EccsiEC.Param_p, _ = new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
	EccsiEC.Param_q, _ = new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
	EccsiEC.Param_B, _ = new(big.Int).SetString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
	EccsiEC.Param_Gx, _ = new(big.Int).SetString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
	EccsiEC.Param_Gy, _ = new(big.Int).SetString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
	EccsiEC.Gx = EccsiEC.Gx.Set(EccsiEC.Param_Gx)
	EccsiEC.Gy = EccsiEC.Gy.Set(EccsiEC.Param_Gy)
	//EccsiEC.P, _ = new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
}