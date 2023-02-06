/* Desp:
 */

package crypto

import (
	//"common/rpc/cc"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"eccsi_sakke_go/consts"
	"encoding/base64"
	"encoding/hex"
	"errors"
	//"consts"
	"io/ioutil"
	"math/big"
	//"sdk/slog"
	slog "github.com/golang/glog"
	"strings"
)

var zero big.Int
var One, _ = new(big.Int).SetString("1", 10) // 全局作用域内可进行任何形式的赋值操作
var Two, _ = new(big.Int).SetString("2", 10)
var Three, _ = new(big.Int).SetString("3", 10)

// Imessage nextPayload value
const (
	M_Last       = iota //0
	M_KEMAC             //1
	M_PKE               //2
	M_DH                //3
	M_SIGN              //4
	M_T                 //5
	M_ID                //6
	M_CERT              //7
	M_CHASH             //8
	M_V                 //9
	M_SP                //10
	M_RAND              //11
	M_ERR               //12
	M_TR                //13
	M_IDR               //14
	M_RANDR             //15
	M_TP                //16
	M_TICKET            //17
	M_KeyData    = 20
	M_GeneralExt = 21
	M_SAKKE      = 26
)

/*******************************************************************************
* 功能说明：	生成user salt 用于异或求GMK-ID
* 参数说明： key: ssv;
			msUri: 带@mcdata.| @mcptt. | @mcvideo.
* 参见文档： KDF算法	[3GPP][33220-h00][Annex B (normative):Specification of the key derivation function KDF][B.2.0 General]
*******************************************************************************/
func calcUserSalt(key []byte, msUri string) uint32 {
	// 1.1 首先需要构造 KDF算法的输入S = FC||P0||L0
	var FC = byte(0x50)
	P0 := msUri
	L0 := len(P0)

	// len(FC)+len(P0)+2 = 1+L0+2
	S := make([]byte, 1+L0+2) // todo-yyl: 此处与C-GMKMS稍不同，没有结束符\0，故少申请1字节
	S[0] = FC
	copy(S[1:], P0)
	S[L0+1] = 0
	S[L0+2] = byte(L0)

	// 1.2 采用KDF算法生成User Salt: HMAC-SHA-256(Key, S)  使用GMK作为key
	hash := hmac.New(sha256.New, key)
	hash.Write(S)
	output := hash.Sum(nil)

	Salt := uint32(output[len(output)-4]) << 24
	Salt += uint32(output[len(output)-3]) << 16
	Salt += uint32(output[len(output)-2]) << 8
	Salt += uint32(output[len(output)-1])

	return Salt
}

/*******************************************************************************
* 功能说明：	生成GUK-ID (Group User Key Identifier)
* 参见文档：	生成算法	[3GPP][33179-d60][7.3.1][Figure 7.3.1-3]
					[3GPP][33179-d60][F.1.3	Calculation of the User Salt for GUK-ID generation]
			KDF算法	[3GPP][33220-h00][Annex B (normative):Specification of the key derivation function KDF][B.2.0 General]
*******************************************************************************/
func GenerateGUKID(ptr *SSVKeyInfo, userUri string) [4]byte {

	// 根据GMK-ID 和 派生自用户标识符的User Salt生成，计算GUK-ID (Group User Key Identifier)
	GMKID := ptr.KeyId
	key := ptr.SSV // SSV 即 GMK  RFC协议参数名--3GPP参数名

	// 1. 计算User Salt
	// 1. 计算User Salt
	Salt := calcUserSalt(key, userUri)

	// 2. User Salt 与 GMK-ID 进行异或运算
	xor := Salt ^ GMKID

	/*
		端到端加密文档：GUK-ID：pupose tag(取值为0)与28 bits的的identifier组成，其中identifier由GMK-ID的随机值与User Salt异或生成；
		[3GPP][33179-d60]描述：
		The 28 least significant bits of the 256 bits of the KDF output shall be used as the User Salt.

		For each user, the GMS creates a 28-bit User Salt by hashing the user's MCPTT ID through a KDF using the GMK as the key as defined in clause F.1.3.
		The User Salt is xor'd with the 28 least-significant bits of the GMK-ID to create the 32 bit GUK-ID.
		The process for generating the GUK-ID is summarized in figure 7.3.1-3.
	*/
	ret := [4]byte{}
	ret[0] = byte((xor & 0x0f000000) >> 24) // Salt与GMK-ID生成时都只取用低28bit，故此处直接丢弃高4bit
	ret[1] = byte((xor & 0xff0000) >> 16)
	ret[2] = byte((xor & 0xff00) >> 8)
	ret[3] = byte(xor & 0xff)

	return ret
}

func GetGMKIDByGUKID(SSV []byte, GUKID [4]byte, userUri string) uint32 {
	var xor uint32 //xor := Salt ^ GMKID
	xor |= uint32(GUKID[0]) << 24
	xor |= uint32(GUKID[1]) << 16
	xor |= uint32(GUKID[2]) << 8
	xor |= uint32(GUKID[3])
	slog.Infof("xor :%v", xor)

	salt := calcUserSalt(SSV, userUri)
	salt &= 0x0fffffff // TODO: 有点不理解
	//slog.Infof("salt1 : %v, GUKID %v", salt, GUKID)
	GMKID := xor ^ salt // xor := Salt ^ GMKID ==> xor ^ Salt =  Salt ^ Salt ^ GMKID ==> GMKID = xor ^ Salt
	return GMKID
}

/*******************************************************************************
* 功能说明：	生成GMK-ID
* Imessage中的CommonHdr中的CSB_ID（即guk_id）, 组号时为 guk_id  和usersalt key 做 异或运算计算出 GMK-ID
*******************************************************************************/
func GenerateGMKID(CSB_ID [4]byte, SSV []byte, userUri string) uint32 {
	salt := calcUserSalt(SSV, userUri)
	slog.Infof("salt2 : %v", salt)
	xor := uint32(CSB_ID[0]) << 24
	xor |= uint32(CSB_ID[1]) << 16
	xor |= uint32(CSB_ID[2]) << 8
	xor |= uint32(CSB_ID[3])

	GMKID := xor ^ salt
	return GMKID
}

/*******************************************************************************
* 功能说明：	生成SAKKE Encapsulated Data
* 参见文档：	[RFC6508][6.2.1. Sender]
			[RFC6508][Appendix A. Test Data]
			[RFC6508][4. Representation of Values][Encapsulated Data]
*******************************************************************************/
func SakkeEncrypt(uid []byte, ptr *SSVKeyInfo, root *MikeyGenRoot) []byte {
	// 1) Select a random ephemeral integer value for the SSV in the range 0 to 2 ^ n - 1;
	// 随机数SSV = ptr.SSV 即 GMK
	slog.Infof("Sakke FormEncapsulatedData SSV: %s, uid: %s", hex.EncodeToString(ptr.SSV), hex.EncodeToString(uid))

	// 2) Compute r = HashToIntegerRange(SSV || b, q, Hash);
	// [RFC6508][Appendix A. Test Data]: ’b’ represents the Identifier of the RespoAES_256nder. 即 入参uid
	ssv_concat_b := make([]byte, 0, len(ptr.SSV)+len(uid)) // SSV || b
	ssv_concat_b = append(ssv_concat_b, ptr.SSV...)
	ssv_concat_b = append(ssv_concat_b, uid...)
	r := SakkeHashToIntegerRange(ssv_concat_b, SakkeEC.Param_q)
	slog.Infof("Sakke FormEncapsulatedData r: %s", hex.EncodeToString(r.Bytes()))

	/***************************************** 耗时代码段-1 begin *****************************************/
	// 3) Compute R_(b, S) = [r]([b]P + Z_S) in E(F_p);
	b := new(big.Int).SetBytes(uid)
	tmpX, tmpY := SakkeEC.ScalarBaseMult(b.Bytes())                          // [b]P    P为椭圆曲线的基准点G b.Bytes()就是uid
	tmpX, tmpY = SakkeEC.Add(tmpX, tmpY, root.EncKeyZ_S.X, root.EncKeyZ_S.Y) // [b]P + Z_S
	R_bSx, R_bSy := SakkeEC.ScalarMult(tmpX, tmpY, r.Bytes())                // [r]([b]P + Z_S)
	slog.Infof("R_bSx %s", hex.EncodeToString(R_bSx.Bytes()))
	slog.Infof("R_bSy %s", hex.EncodeToString(R_bSy.Bytes()))

	/***************************************** 耗时代码段-2 begin *****************************************/
	// 4) Compute the Hint, H;
	//    a) Compute g^r.
	if ret := r.Cmp(&zero); 0 == ret {
		slog.Error("Compute g^r but r is zero, failed.")
		return nil
	}
	tmp_p := new(big.Int).Set(SakkeEC.Param_p)
	resX := new(big.Int)
	resY := new(big.Int)

	// todo-yyl: 如下计算 g^r过程暂未理解
	SakkePointExponent(tmp_p, resX, resY, One, SakkeEC.Param_g, r)
	g_power_r := new(big.Int).Mod(resX, tmp_p)
	g_power_r.ModInverse(g_power_r, tmp_p)
	g_power_r.Mul(g_power_r, resY)
	g_power_r.Mod(g_power_r, tmp_p) // g^r
	slog.Infof("Sakke FormEncapsulatedData g^r: %s", hex.EncodeToString(g_power_r.Bytes()))

	//    b) Compute H : = SSV XOR HashToIntegerRange(g^r, 2^n, Hash);
	two_power_n := new(big.Int).SetBit(&zero, int(ptr.SSVLen*8), 1) // 2^n  n==SAKKE对称密钥GMK的bit位数--SSV的bit位数

	// [RFC6508][Appendix A. Test Data]: The value "mask" is the value used to mask the SSV and is defined to be HashToIntegerRange(g^r, 2^n, Hash)
	mask := SakkeHashToIntegerRange(g_power_r.Bytes(), two_power_n)
	slog.Infof("mask[%d] %s", len(mask.Bytes()), hex.EncodeToString(mask.Bytes()))

	H := new(big.Int).SetBytes(ptr.SSV) // len(H) = len(SSV) aes_128, len(SSV) = 16; aes_256, len(SSV) = 32;
	H = H.Xor(H, mask)                  // H = SSV xor mask
	slog.Infof("H %s", hex.EncodeToString(H.Bytes()))

	// 5) Form the Encapsulated Data(R_(b, S), H), and transmit it to B;
	// Encapsulated Data的定义见[4. Representation of Values][Encapsulated Data]
	// Encapsulated Data由 椭圆曲线上的点与integer数 连接构成，即 R_(b, s) 连接 H 等于 0x04||Rx||Ry||H
	offset := 0
	encapsulatedDataLen := 1 + (SAKKE_XY_BYTES * 2) + ptr.SSVLen // Tips: AES128/AES256媒体加密类型不同，Encapsulated Data长度不同
	encapsulatedData := make([]byte, encapsulatedDataLen)
	slog.Infof("encapsulatedDataLen 0x%x", encapsulatedDataLen)

	// 0x04||Rx||Ry||H
	encapsulatedData[0] = 0x04 // 椭圆曲线点以 0x04 打头
	offset += 1

	offset += SAKKE_XY_BYTES - len(R_bSx.Bytes()) // Tips: 坐标数值的字节数不足 SAKKE_XY_BYTES(128)，则填充0
	copy(encapsulatedData[offset:], R_bSx.Bytes())

	offset += len(R_bSx.Bytes()) + SAKKE_XY_BYTES - len(R_bSy.Bytes())
	copy(encapsulatedData[offset:], R_bSy.Bytes())

	offset += len(R_bSy.Bytes()) + int(ptr.SSVLen) - len(H.Bytes()) // H字节数不足 SSVLen，则填充0
	copy(encapsulatedData[offset:], H.Bytes())

	slog.Infof("encapsulatedData %v", encapsulatedData)
	return encapsulatedData
}

/***************************************************************************//**
* Validates the RSK provided by the KMS for use by this user.
*	(校验加密私钥)
*     RFC6508 6.1.2 (para 2)
*     ----------------------
*
*     Upon receipt of key material, each user MUST verify its RSK. For
*     Identifier 'a', RSKs from KES_T are verified by checking that the
*     following equation holds: < [a]P + Z, K_(a,T) > = g, where 'a' is
*     interpreted as an integer.
******************************************************************************/
func sakkeValidateRSK(userId, RSK []byte, EncKeyZ_S EC_POINT) bool {
	RSK_len := len(RSK)
	RSKx, RSKy := RSK[1:RSK_len/2+1], RSK[RSK_len/2+1:]
	Zx, Zy := EncKeyZ_S.X, EncKeyZ_S.Y

	slog.Infof("sakke validateRSK start userId %s, RSK %s", string(userId), string(RSK))
	//START PROCESS AS PER RFC 6508 SECTION 6.1.2
	//1) The following MUST hold < [a]P + Z, K_(a,T) > = g,"where a is interpreted as an integer"

	//  Z:/ Z_point);
	//   K_(a,T) aka Kb(RFC 6508 Appendix A, page 18):" RSK_point
	a_P_plus_Z_point_x, a_P_plus_Z_point_y := EccsiEC.ScalarBaseMult(userId) // 关于Gx Gy与P的关系有疑问

	// [a]P: a_P_plus_Z_point
	a_P_plus_Z_point_x, a_P_plus_Z_point_y = EccsiEC.Add(a_P_plus_Z_point_x, a_P_plus_Z_point_y, Zx, Zy)

	result := new(big.Int)
	SakkeComputeTLPairing(result, a_P_plus_Z_point_x, a_P_plus_Z_point_y, new(big.Int).SetBytes(RSKx), new(big.Int).SetBytes(RSKy))
	slog.Infof("sakke validateRSK Sakke computeTLPairing a_P_plus_Z_point_x %v, a_P_plus_Z_point_y %v, result %v", a_P_plus_Z_point_x, a_P_plus_Z_point_y, *result)

	// < [a]P + Z, K_(a,T) >:", 8, a_P_plus_Z_point
	if result.Cmp(SakkeEC.Param_g) != 0 {
		slog.Error("sakke validateRSK Sakke computeTLPairing result %v not equal Param_g %v", *result, SakkeEC.Param_g)
		return false
	}

	slog.Infof("sakke validateRSK Sakke success!!!")

	return true
}

/*******************************************************************************
* 功能说明：	提取SAKKE Encapsulated Data，即取出共享秘钥ssv
* 参数说明： rsk为UserDecryptKey，即用户解密私钥
* 参见文档：	[RFC6508][6.2.2. Receiver]
			[RFC6508][Appendix A. Test Data]
			[RFC6508][4. Representation of Values][Encapsulated Data]
*******************************************************************************/
func SakkeDecrypt(sakkeData []byte, enType consts.EncAlgoType, root *MikeyGenRoot) ([]byte, error) {
	// 1) parse (R_b, S, H) and extract R_(b, S) and H
	// sakkeData = 0x04||Rx||Ry||H, len(Rx) = SAKKE_XY_BYTES, len(Ry) = SAKKE_XY_BYTES, R_(b, S)由Rx、Ry组成
	// len(H) = len(SSV) aes_128, len(SSV) = 16; aes_256, len(SSV) = 32.
	R_bSx, R_bSy, H := sakkeData[1:1+SAKKE_XY_BYTES], sakkeData[1+SAKKE_XY_BYTES:1+SAKKE_XY_BYTES*2], sakkeData[1+SAKKE_XY_BYTES*2:]
	R_x, R_y := new(big.Int).SetBytes(R_bSx), new(big.Int).SetBytes(R_bSy) // 转成big.Int用于 2）计算w值
	slog.Infof("Sakke ExtactShareSecret userUri: %s", root.UserUri)
	//slog.Infof("Sakke ExtactShareSecret R_bSx: %s", hex.EncodeToString(R_bSx))
	//slog.Infof("Sakke ExtactShareSecret R_bSy: %s", hex.EncodeToString(R_bSy))
	slog.Infof("Sakke ExtactShareSecret H: %v", hex.EncodeToString(H))

	// R_(b, s)从压缩数据中解析出来，K_(b, s)需要根据R_(b, s)计算方法计算？ 文档描述 K_(b, s) 由kms预先设置，但并没看到kms有对这个值计算，但从ICE puc 网关实现看就是rsk，这里按ICE puc 网关实现
	Q_x, Q_y := root.RSK.X, root.RSK.Y
	//slog.Infof("R_bSx %s", hex.EncodeToString(R_bSx.Bytes()))
	//	//slog.Infof("R_bSy %s", hex.EncodeToString(R_bSy.Bytes()))

	// 2) Compute w := < R_(b,S), K_(b,S) >.  Note that by bilinearity, w = g^r;
	w := new(big.Int)
	if !SakkeComputeTLPairing(w, R_x, R_y, Q_x, Q_y) {
		errStr := "Sakke ExtactShareSecret compute TL Paring err"
		slog.Error(errStr)
		return nil, errors.New(errStr)
	}
	slog.Infof("Sakke ExtactShareSecret w: %s", hex.EncodeToString(w.Bytes()))

	// 3) Compute SSV = H XOR HashToIntegerRange( w, 2^n, Hash );
	ssvLen := consts.AES_128_BITS
	if enType == consts.AlgoAes256 {
		ssvLen = consts.AES_256_BITS
	}
	two_power_n := new(big.Int).SetBit(&zero, ssvLen, 1) // 2^n  n==SAKKE对称密钥GMK的bit位数--SSV的bit位数

	// [RFC6508][Appendix A. Test Data]: The value "mask" is the value used to mask the SSV and is defined to be HashToIntegerRange(w, 2^n, Hash)
	mask := SakkeHashToIntegerRange(w.Bytes(), two_power_n)
	slog.Infof("Sakke ExtactShareSecret mask[%d] %v", len(mask.Bytes()), hex.EncodeToString(mask.Bytes()))

	SSV := new(big.Int).SetBytes(H)
	SSV = SSV.Xor(SSV, mask) // H = SSV xor mask ==> H xor mask = SSV xor mask xor mask ==> SSV = H xor mask, 任何数异或x两次等于它自己，任何数异或0等于它自己
	slog.Infof("Sakke ExtactShareSecret SSV %s", hex.EncodeToString(SSV.Bytes()))

	// 4) Compute r = HashToIntegerRange( SSV || b, q, Hash );
	// [RFC6508][Appendix A. Test Data]: ’b’ represents the Identifier of the Responder. 即 入参uid
	SSV_bytes := SSV.Bytes()
	ssv_concat_b := make([]byte, 0, len(SSV_bytes)+len(root.UID)) // SSV || b
	ssv_concat_b = append(ssv_concat_b, SSV_bytes...)
	ssv_concat_b = append(ssv_concat_b, root.UID...)
	r := SakkeHashToIntegerRange(ssv_concat_b, SakkeEC.Param_q)
	slog.Infof("Sakke ExtactShareSecret 4) Compute r %s", hex.EncodeToString(r.Bytes()))
	slog.Infof("Sakke ExtactShareSecret 4) Compute r  ssv_concat_b: %s, UID: %s", hex.EncodeToString(ssv_concat_b), hex.EncodeToString(root.UID))

	// 5) Compute TEST = [r]([b]P + Z_S) in E(F_p).  If TEST does not
	//	  equal R_(b,S), then B MUST NOT use the SSV to derive key
	//	  material;
	b := new(big.Int).SetBytes(root.UID)
	tmpX, tmpY := SakkeEC.ScalarBaseMult(b.Bytes())                          // [b]P    P为椭圆曲线的基准点G b.Bytes()就是uid
	tmpX, tmpY = SakkeEC.Add(tmpX, tmpY, root.EncKeyZ_S.X, root.EncKeyZ_S.Y) // [b]P + Z_S
	T_R_bSx, T_R_bSy := SakkeEC.ScalarMult(tmpX, tmpY, r.Bytes())            // [r]([b]P + Z_S)
	slog.Infof("Sakke ExtactShareSecret R_bSx: %s", hex.EncodeToString(R_bSx))
	slog.Infof("Sakke ExtactShareSecret T_R_bSx %s", hex.EncodeToString(T_R_bSx.Bytes()))
	slog.Infof("Sakke ExtactShareSecret R_bSy: %s", hex.EncodeToString(R_bSy))
	slog.Infof("Sakke ExtactShareSecret T_R_bSy %s", hex.EncodeToString(T_R_bSy.Bytes()))

	if T_R_bSx.Cmp(R_x) != 0 || T_R_bSy.Cmp(R_y) != 0 {
		slog.Error("Sakke ExtactShareSecret TEST(T_R_bSx, T_R_bSy) does not equal R_(b,S)")
		return nil, errors.New("TEST does not equal R_(b,S)")
	}

	slog.Infof("ExtactShareSecret ok SSV %s", hex.EncodeToString(SSV.Bytes()))

	return SSV.Bytes(), nil
}

/*******************************************************************************
* 功能说明：	计算The Tate-Lichtenbaum Paring， 即compute w = <R_(b, s), K_(b, s)>; 根据双曲线特性w = g^r， g^r在压缩时有求得
* 参见文档：	[RFC6508][3.2. The Tate-Lichtenbaum Paring]
			[RFC6508][Appendix A. Test Data]
			[RFC6508][2.1. Notation][affine coordinates (x,y) ]
*******************************************************************************/
func SakkeComputeTLPairing(w, Rx, Ry, RSKx, RSKy *big.Int) bool {
	Vx, _ := new(big.Int).SetString("1", 10) // v的x坐标，v = (F_p)*;    // An element of PF_p[q]
	Vy, _ := new(big.Int).SetString("0", 10) // v的y坐标，v = (F_p)*;    // An element of PF_p[q]
	tmp_t := new(big.Int)
	T_x1 := new(big.Int)
	T_x2 := new(big.Int)
	t := new(big.Int)
	p := new(big.Int).Set(SakkeEC.Param_p)

	Cx, Cy := new(big.Int).Set(Rx), new(big.Int).Set(Ry) // C = R;  An element of E(F_p)[q]
	Qx, Qy := new(big.Int).Set(RSKx), new(big.Int).Set(RSKy)

	// for bits of q-1, starting with the second most significant bit, ending with the least significant bit
	q_minus_one := new(big.Int).Sub(SakkeEC.Param_q, One)
	N := q_minus_one.BitLen() - 1
	for ; N != 0; N-- {
		SakkePointSquare(p, Vx, Vy, Vx, Vy) // v = v^2

		T_x1.Mul(Cx, Cx) // T_x1 = C_x^2
		T_x1.Mod(T_x1, p)
		T_x1.Sub(T_x1, One)   // T_x1 = C_x^2 - 1
		T_x1.Mul(T_x1, Three) // T_x1 = 3*(C_x^2 - 1)

		t.Add(Qx, Cx) // t = Q_x + C_x

		T_x1.Mul(T_x1, t) // T_x1 = 3*(C_x^2 - 1)*(Q_x + C_x)
		T_x1.Mod(T_x1, p)

		t.Mul(Cy, Cy) // t = C_y^2
		t.Mod(t, p)

		t.Mul(t, Two)     // t = 2 * C_y^2
		T_x1.Sub(T_x1, t) // T_x1 = 3*(C_x^2 - 1)*(Q_x + C_x) - 2 * C_y^2
		T_x1.Mod(T_x1, p)

		T_x2.Mul(Cy, Two)  // T_x2 = 2*C_y
		T_x2.Mul(T_x2, Qy) // T_x2 = 2*C_y*Q_y
		T_x2.Mod(T_x2, p)

		SakkePointsMultiply(p, Vx, Vy, Vx, Vy, T_x1, T_x2)

		/* Doubling EC point
		 * (it is known the C is not at infinity)
		 */
		sakkePointMultiply(p, Cx, Cy, Cx, Cy, Two)

		// if bit is 1, then
		if 1 == q_minus_one.Bit(N-1) {
			T_x1.Add(Qx, Rx)
			T_x1.Mul(T_x1, Cy)
			T_x1.Mod(T_x1, p)
			tmp_t.Add(Qx, Cx)
			tmp_t.Mul(tmp_t, Ry)
			T_x1.Sub(T_x1, tmp_t)
			T_x1.Mod(T_x1, p)
			T_x2.Sub(Cx, Rx)
			T_x2.Mul(T_x2, Qy)
			T_x2.Mod(T_x2, p)

			SakkePointsMultiply(p, Vx, Vy, Vx, Vy, T_x1, T_x2)

			// Addition of EC points R and C
			// (it is known that neither R nor C are at infinity)
			SakkePointsAdd(p, Cx, Cy, Rx, Ry, Cx, Cy)
		}
	}

	SakkePointSquare(p, Vx, Vy, Vx, Vy)
	SakkePointSquare(p, Vx, Vy, Vx, Vy)
	w.ModInverse(Vx, p)
	w.Mul(w, Vy)
	w.Mod(w, p)

	return true
}

// multiplier 为何没用到？
func sakkePointMultiply(p, result_x, result_y, point_x, point_y, multiplier *big.Int) {
	lambda := new(big.Int)
	lambda_sq := new(big.Int)
	EAT1 := new(big.Int)
	EARx := new(big.Int)
	EARy := new(big.Int)

	lambda.Mul(point_x, point_x)
	lambda.Mod(lambda, p)

	lambda.Sub(lambda, One)
	lambda.Mul(lambda, Three)

	EAT1.Mul(point_y, Two)

	// Should check NULL here if inverse cannot be found!
	EAT1.ModInverse(EAT1, p)

	lambda.Mul(lambda, EAT1)
	lambda.Mod(lambda, p)

	lambda_sq.Mul(lambda, lambda)
	lambda_sq.Mod(lambda_sq, p)

	EAT1.Mul(point_x, Two)
	EARx.Sub(lambda_sq, EAT1)
	EARx.Mod(EARx, p)

	EARy.Sub(EAT1, lambda_sq)
	EARy.Add(EARy, point_x)
	EARy.Mul(EARy, lambda)
	EARy.Mod(EARy, p)

	EARy.Sub(EARy, point_y)
	EARy.Mod(EARy, p)

	result_x = result_x.Set(EARx)
	result_y = result_y.Set(EARy)
}

func SakkePointsAdd(p, result_x, result_y, point_1_x, point_1_y, point_2_x, point_2_y *big.Int) {
	lambda := new(big.Int)
	lambda_sq := new(big.Int)
	EAT1 := new(big.Int)
	EARx := new(big.Int)
	EARy := new(big.Int)

	lambda.Sub(point_1_y, point_2_y)
	EAT1.Sub(point_1_x, point_2_x)

	// TBD - Should check NULL here if inverse cannot be found!!!
	EAT1.ModInverse(EAT1, p)

	lambda.Mul(lambda, EAT1)
	lambda.Mod(lambda, p)

	lambda_sq.Mul(lambda, lambda)
	lambda_sq.Mod(lambda_sq, p)

	EARx.Sub(lambda_sq, point_2_x)
	EARx.Sub(EARx, point_1_x)
	EARx.Mod(EARx, p)

	EARy.Sub(point_1_x, lambda_sq)

	point_2_x.Mul(point_2_x, Two)
	EARy.Add(EARy, point_2_x)

	EARy.Mul(EARy, lambda)
	EARy.Mod(EARy, p)

	EARy.Sub(EARy, point_2_y)
	EARy.Mod(EARy, p)

	result_x.Set(EARx)
	result_y.Set(EARy)
}

/*******************************************************************************
* 功能说明：	HashToIntegerRange函数实现
* 参见文档：	[RFC6508][5.1. Hashing to an Integer Range]
			[RFC6508][2.1. Notation] lg(x): The base 2 logarithm of the real value x
*******************************************************************************/
func SakkeHashToIntegerRange(s []byte, n *big.Int) *big.Int {
	// Hash算法并不固定，编码采用SHA-256原因，见[RFC6508][Appendix A. Test Data]
	hash_len := sha256.Size * 8 // hash算法输出的bit位数
	slog.Infof("hash_len %d", hash_len)

	// 1) Let A = hashfn(s)
	hashA := sha256.New()
	hashA.Write(s)
	A := hashA.Sum(nil)
	slog.Infof("A[%d] %v", len(A), A)

	// 2) Let h_0 = 00...00 is a string of null bits of length hash_len bits.
	h_i := make([]byte, hash_len/8) // h_i初始值所有bit位全0，即 h_0

	// 3) l = ceiling(lg(n)/hashlen)
	l := (n.BitLen() + 255) >> 8
	vprime := make([]byte, l*sha256.Size) // vprime 即 v'
	slog.Infof("vprime[%d]", len(vprime))

	// 4) For i in [1, l] do
	for i := 0; i < l; i++ {
		// a) Let h_i = hashfn(h_(i - 1))   // 1.首次for循环:hash输入为h_0; 2.其他for循环:上次hash结果作为本次hash的输入;
		hash_h_i := sha256.New()
		hash_h_i.Write(h_i)
		h_i = hash_h_i.Sum(nil)

		// b) Let v_i = hashfn(h_i || A) where || denotes concatenation.
		h_i_concat_A := make([]byte, len(h_i)+len(A))
		copy(h_i_concat_A, h_i)
		copy(h_i_concat_A[len(h_i):], A)

		hash_v_i := sha256.New()
		hash_v_i.Write(h_i_concat_A)
		v_i := hash_v_i.Sum(nil)
		slog.Infof("v_i[%d] %v", len(v_i), v_i)

		// 5) Let v' = v_1 || ...  || v_l
		copy(vprime[i*sha256.Size:], v_i)
	}
	slog.Infof("vprime[%d] %v", len(vprime), vprime)

	// 6) v = v' mod n
	v := new(big.Int).SetBytes(vprime)
	v.Mod(v, n) // 模结果总是 0 或 正整数
	return v
}

func SakkePointSquare(p, result_x, result_y, point_x, point_y *big.Int) {
	tmp_Ax1 := new(big.Int).Set(point_x)
	tmp_Ax2 := new(big.Int).Set(point_y)

	tmp_Bx1 := new(big.Int).Add(point_x, point_y)
	tmp_Bx2 := new(big.Int).Sub(point_x, point_y)

	result_x.Mul(tmp_Bx1, tmp_Bx2)
	result_x.Mod(result_x, p)

	result_y.Mul(tmp_Ax1, tmp_Ax2)
	result_y.Mul(result_y, Two)
	result_y.Mod(result_y, p)
}

func SakkePointsMultiply(p, result_x, result_y, point_1_x, point_1_y, point_2_x, point_2_y *big.Int) {
	res_x := new(big.Int).Mul(point_1_x, point_2_x)
	tmp := new(big.Int).Mul(point_1_y, point_2_y)

	res_x.Sub(res_x, tmp)
	res_x.Mod(res_x, p)

	res_y := new(big.Int).Mul(point_1_x, point_2_y)
	tmp.Mul(point_1_y, point_2_x)
	res_y.Add(res_y, tmp)
	res_y.Mod(res_y, p)

	result_x.Set(res_x)
	result_y.Set(res_y)
}

func SakkePointExponent(p, result_x, result_y, point_x, point_y, n *big.Int) {
	if 0 == n.Cmp(&zero) {
		slog.Error("failed: n == 0")
		return
	}

	result_x.Set(point_x)
	result_y.Set(point_y)

	N := n.BitLen() - 1
	for ; N != 0; N-- {
		SakkePointSquare(p, result_x, result_y, result_x, result_y)
		if 1 == n.Bit(N-1) {
			SakkePointsMultiply(p, result_x, result_y, result_x, result_y, point_x, point_y)
		}
	}
}

/*******************************************************************************
* 功能说明：	Eccsi签名
* 参见文档：	[RFC6507][5.2.1.Algorithm for Signing]
*******************************************************************************/
const maxTry = 5

func EccsiSignature(message []byte, root *MikeyGenRoot) []byte {
	var signature []byte
	slog.Infof("Eccsi signature start message: %s", hex.EncodeToString(message))

	count := 0
	for ; count < maxTry; count++ {
		// 1) Choose a random(ephemeral) non - zero value j in F_q;
		// 如何理解 j 在F_q上？ 参见[RFC6507][3.2. Representations][F_p elements]
		// Tips: C-GMKMS历史版本实现方式: 先取随机数，再模EccsiEC.Param_q，保证 j落在范围(0, q)内
		// Go-GMKMS 选择j的实现：
		j, _ := rand.Int(rand.Reader, EccsiEC.Param_q) // todo-yyl: 这样做是否会影响到后续的 签名长度呢？
		if 0 == j.Cmp(&zero) {
			slog.Warning("j equals 0, add 1.")
			j.Add(j, One)
		}
		if 0 == j.Cmp(EccsiEC.Param_q) {
			slog.Warning("j equals q, sub 1.")
			j.Sub(j, One)
		}
		slog.Infof("j[%d] %v", len(j.Bytes()), hex.EncodeToString(j.Bytes()))

		// 2) Compute J = [j]G
		// Viewing J in affine coordinates J = (Jx, Jy), assign to r the N - octet integer representing Jx
		Jx, _ := EccsiEC.ScalarBaseMult(j.Bytes())
		r := Jx
		slog.Infof("Jx EccsiEC Gx %s, Gy %s", hex.EncodeToString(EccsiEC.Gx.Bytes()), hex.EncodeToString(EccsiEC.Gy.Bytes()))
		slog.Infof("Jx %s", hex.EncodeToString(Jx.Bytes()))

		// 3) Recall(or recompute) HS, and use it to compute a hash value HE = hash(HS || r || M);
		r_bytes := r.Bytes()
		r_len := len(r_bytes)
		if r_len < ECCSI_N {
			slog.Warning("length[%d] of r is less than %d, need to pad 0.", r_len, ECCSI_N)
			tmp := make([]byte, ECCSI_N)
			copy(tmp[ECCSI_N-r_len:], r_bytes) // C-GMKMS历史版本 字节数不足ECCSI_N，前面填充0
			r_bytes = tmp
			r_len = len(r_bytes)
		}
		//slog.Infof("r_bytes[%d] %v", r_len, r_bytes) // 至此已确保 r_bytes 非0且长度 ECCSI_N
		slog.Infof("r_bytes %s", hex.EncodeToString(r_bytes))

		HE_bytes := computeHE(root.HS, r_bytes, message)
		HE := new(big.Int).SetBytes(HE_bytes)
		slog.Infof("HE %s", hex.EncodeToString(HE_bytes))

		// 4) Verify that HE + r * SSK is non-zero modulo q;
		midRes := new(big.Int).Mul(r, root.SSK)
		midRes.Add(midRes, HE) // HE + r * SSK
		tmp := new(big.Int).Mod(midRes, EccsiEC.Param_q)
		// if this check fails, the Signer MUST abort or restart this procedure with a fresh value of j;
		if 0 == tmp.Cmp(&zero) {
			slog.Error("[%d] (HE + r * SSK) mod q == 0, continue.", count)
			continue
		}

		// 5) Compute s’ = ( (( HE + r * SSK )^-1) * j ) modulo q;
		sprime := new(big.Int).ModInverse(midRes, EccsiEC.Param_q)
		sprime.Mul(sprime, j)
		sprime.Mod(sprime, EccsiEC.Param_q)
		// the Signer MUST then erase the value j;
		j.Set(&zero)

		// 6) If s’ is too big to fit within an N-octet integer, then set the N-octet integer s = q - s’;
		// otherwise, set the N-octet integer s = s’
		if len(sprime.Bytes()) > ECCSI_N { // if s’ > 2^n
			slog.Warning("s’ is too big, set s = q - s’ ")
			sprime.Sub(EccsiEC.Param_q, sprime) // Tips: 由于编码取固定的q值，故由协议描述可知: 此时 sprime小于0
			if -1 == sprime.Sign() {
				slog.Warning("s’ is less than 0")
			}
		}
		s := sprime // 至此已确保 s.Bytes() 不可能大于 ECCSI_N

		// 7) Output the signature as Signature = (r || s || PVT).
		s_bytes := s.Bytes()
		s_len := len(s_bytes)
		slog.Infof("s_len %d", s_len)

		// Tips: 此处拼接的是 PVT数值类型的16进制字节序列，而非PVT的16进制字符串
		signatureLen := ECCSI_N + ECCSI_N + len(root.PVT)
		slog.Infof("signatureLen 0x%x", signatureLen)

		signature = make([]byte, signatureLen)

		offset := 0
		copy(signature[offset:], r_bytes)
		offset += len(r_bytes)

		offset += ECCSI_N - s_len
		copy(signature[offset:], s_bytes)
		offset += s_len

		copy(signature[offset:], root.PVT)

		slog.Infof("signature[%d] %s", len(signature), hex.EncodeToString(signature))

		break // 至此成功，不用重试
	}

	if maxTry == count {
		slog.Fatal("%d retries failed, return nil.", maxTry)
	}

	slog.Infof("Signature %s", hex.EncodeToString(signature))
	return signature
}

/***************************************************************************//**
	* Validate a received (from KMS) SSK (RFC 6507 Section 5.1.2)
	* (校验签名私钥)
	* Every SSK MUST be validated before being installed as a signing key.
	* The Signer uses its ID and the KPAK to validate a received (SSK,PVT)
	* pair.
 	* @param KPAK kms的签名公钥（ECCSI的公共密钥 KPAK 用于ECCSI Sign发送数据）
******************************************************************************/
func eccsiValidateSSK(root *MikeyGenRoot) bool {
	// 1) Validate that the PVT lies on the curve E
	PVT_len := len(root.PVT)
	PVTx, PVTy := new(big.Int).SetBytes(root.PVT[1:1+PVT_len/2]), new(big.Int).SetBytes(root.PVT[1+PVT_len/2:])
	//EccsiEC.IsOnCurve(PVTx, PVTy)// InitMikeyGenRoot 对PVT做过校验

	// 2) Compute HS = hash( G || KPAK || ID || PVT ) InitMikeyGenRoot已经计算了

	// 3) Validate that KPAK = [SSK]G - [HS]PVT
	// LHS == [HS]PVT + KPAK and RHS == [SSK]G
	//"[HS]PVT - Multiply by PVT by HS"
	HS_PVT_ProductX, HS_PVT_ProductY := EccsiEC.ScalarMult(PVTx, PVTy, root.HS)

	// LHS = [HS]PVT + KPAK
	eccsiXYBytes := len(root.KPAK)
	KPAKx := new(big.Int).SetBytes(root.KPAK[1 : eccsiXYBytes+1])
	KPAKy := new(big.Int).SetBytes(root.KPAK[eccsiXYBytes+1:])
	LHSx, LHSy := EccsiEC.Add(HS_PVT_ProductX, HS_PVT_ProductY, KPAKx, KPAKy)

	// RHS = SSK[G] 和 [SSK]G区别呢？ 从ICE c++代码翻译是用ScalarBaseMult
	RHSx, RHSy := EccsiEC.ScalarBaseMult(root.SSK.Bytes())

	// LHS (KPAK + [HS]PVT) == RHS ([SSK]G)
	if LHSx.Cmp(RHSx) != 0 || LHSy.Cmp(RHSy) != 0 {
		slog.Infof("eccsi validateSSK cmp fail LHSx %v, LHSy %v, RHSx %v, RHSy %v", LHSx, LHSy, RHSx, RHSy)
	}
	slog.Infof("eccsi validateSSK success userUri %s, ssk %v", root.UID, root.SSK)
	return true
}

/*******************************************************************************
* 功能说明：	Eccsi验证签名
* 参见文档：	[RFC6507][Verifies an ECCSI signature following the Actions described in section 5.2.2]
* message：  Octet string of the 'message' that was signed
* signature: 签名值 = r||s||pvt, len(r) = 32, len(s)=32, len(pvt)=65
* hs: HS = hash( G || KPAK || ID || PVT ), ID为mikey生成者的UID，PVT为mikey生成者的签名公钥
* kpak： kms的公共认证秘钥
* pvt： 签名验证公钥
*******************************************************************************/
func EccsiVerify(message, signature []byte, UID []byte, root *MikeyGenRoot) bool {
	r, s, pvt := signature[0:ECCSI_N], signature[ECCSI_N:ECCSI_N+ECCSI_N], signature[ECCSI_N+ECCSI_N:] // r, s, pvtx是16进制的值类型？计算时是否需要转成hex？

	// 3) compute a hash value HE = hash(HS || r || M);
	HS := ComputeHs(UID, root.KPAK, pvt)
	if IsTest {
		HS = root.HS
	}
	HE_bytes := computeHE(HS, r, message)
	slog.Infof("Eccsi Verify start r: %s", hex.EncodeToString(r))
	slog.Infof("Eccsi Verify start s: %s", hex.EncodeToString(s))
	slog.Infof("Eccsi Verify start pvtx : %s", hex.EncodeToString(pvt))
	slog.Infof("Eccsi Verify start message: %s", hex.EncodeToString(message))
	slog.Infof("Eccsi Verify start HE: %s", hex.EncodeToString(HE_bytes))

	eccsiXYBytes := (len(root.PVT) - 1) / 2 // len-1 表示去掉前缀字节 0x04
	//PVTx := new(big.Int).SetBytes(root.PVT[1 : eccsiXYBytes+1])
	//PVTy := new(big.Int).SetBytes(root.PVT[eccsiXYBytes+1:])
	PVTx := new(big.Int).SetBytes(pvt[1 : eccsiXYBytes+1])
	PVTy := new(big.Int).SetBytes(pvt[eccsiXYBytes+1:])

	// [HS]PVT
	HS_PVT_ProductX, HS_PVT_ProductY := EccsiEC.ScalarMult(PVTx, PVTy, HS)

	// KPAK
	slog.Infof("KPAK[%d] %v", len(root.KPAK), root.KPAK)
	eccsiXYBytes = (len(root.KPAK) - 1) / 2
	if eccsiXYBytes != ECCSI_XY_BYTES {
		slog.Warning("eccsiXYBytes[%d] != %d", eccsiXYBytes, ECCSI_XY_BYTES)
	}
	KPAKx := new(big.Int).SetBytes(root.KPAK[1 : eccsiXYBytes+1])
	KPAKy := new(big.Int).SetBytes(root.KPAK[eccsiXYBytes+1:])

	// 4)Y = [HS]PVT + KPAK
	resX, resY := EccsiEC.Add(KPAKx, KPAKy, HS_PVT_ProductX, HS_PVT_ProductY)
	slog.Infof("Eccsi Verify Y: %s", hex.EncodeToString(resX.Bytes())+hex.EncodeToString(resY.Bytes()))

	// 5) Compute J = [s]([HE]G + [r]Y)
	HE_G_ProductX, HE_G_ProductY := EccsiEC.ScalarBaseMult(HE_bytes)                    // [HE]G
	r_Y_ProductX, r_Y_ProductY := EccsiEC.ScalarMult(resX, resY, r)                     // [r]Y
	tmpX, tmpY := EccsiEC.Add(HE_G_ProductX, HE_G_ProductY, r_Y_ProductX, r_Y_ProductY) // [HE]G + [r]Y
	Jx, _ := EccsiEC.ScalarMult(tmpX, tmpY, s)                                          // [s]([HE]G + [r]Y)
	slog.Infof("Eccsi Verify Jx: %s", hex.EncodeToString(Jx.Bytes()))

	// 6) affine coordinates(Jx, Jy), must check Jx = r module p, and Jx module p is non-zero
	rBigInt := new(big.Int).SetBytes(r)
	r_mod_p := new(big.Int).Mod(rBigInt, EccsiEC.Param_p)
	if 0 != r_mod_p.Cmp(Jx) {
		slog.Error("Eccsi Verify Jx not equal r_mod_p(%v)", hex.EncodeToString(r_mod_p.Bytes()))
		return false
	}
	Jx_mod_p := new(big.Int).Mod(Jx, EccsiEC.Param_p)
	if 0 == Jx_mod_p.Cmp(big.NewInt(0)) {
		slog.Error("Eccsi Verify Jx(%v) module p(%v) Jx_mod_p(%v) is zero", Jx, EccsiEC.Param_p, Jx_mod_p)
		return false
	}

	slog.Infof("Eccsi Verify success r: %v, s: %v, pvtx : %v, message: %v, HE_bytes: %v", r, s, pvt, message, HE_bytes)

	return true
}

/*******************************************************************************
* 功能说明：	HE = hash( HS || r || M )
* 参见文档：	[RFC6507][5.2.1. Algorithm for Signing]
*******************************************************************************/
func computeHE(hs, r, message []byte) []byte {
	hash := sha256.New()
	hash.Write(hs)
	hash.Write(r)
	hash.Write(message)
	output := hash.Sum(nil)
	return output
}

/*******************************************************************************
* 功能说明： 生成MIKEY-SAKKE UID
* 输入参数：	serviceId	如 sip:6009755001@mcptt.mcs.com
* 输出参数：	UID
* 参见文档： [3GPP][33180-f30][F.2.1 Generation of MIKEY-SAKKE UID]
*******************************************************************************/
func GenerateUID(serviceId string) []byte {
	// 首字节+字符串+字符串长度: 0x00 + "MIKEY-SAKKE-UID" + 0x000f
	first := []byte{
		0x00, 0x4d, 0x49, 0x4b, 0x45, 0x59, 0x2d, 0x53, 0x41, 0x4b,
		0x4b, 0x45, 0x2d, 0x55, 0x49, 0x44, 0x00, 0x0f,
	}

	third := []byte{
		0x00, 0x00, 0x6b, 0x6d, 0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d,
		0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x0f, 0x49,
		0x6c, 0xeb, 0xb8, 0x00, 0x00, 0x05, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x01,
	}
	third[1] = byte(len(serviceId))

	length := len(first) + len(serviceId) + len(third)
	b_need_hash := make([]byte, 0, length)
	b_need_hash = append(b_need_hash, first...)
	b_need_hash = append(b_need_hash, []byte(serviceId)...)
	b_need_hash = append(b_need_hash, third...)

	hash := sha256.New()
	hash.Write(b_need_hash)
	uid := hash.Sum(nil)
	slog.Infof("serviceId[%s] uid[%s]", serviceId, hex.EncodeToString(uid))
	return uid
}

//讲mikey还原成IMessage结构
func ParseImessageData(mikey string, iMsg *IMessage) (signedData []byte) {
	//decodeMikey, _ := base64.StdEncoding.DecodeString(crypto)
	reader := strings.NewReader(mikey)
	decoder := base64.NewDecoder(base64.StdEncoding, reader)
	//decoder.Read(crypto)
	decodeMikey, _ := ioutil.ReadAll(decoder)
	slog.Infoln("Parse Imessage Data mikey %v", mikey)

	index := 0 // 索引下表

	var hdr CommonHeader
	hdr.Version = decodeMikey[index]
	hdr.DataType = decodeMikey[index+1]
	hdr.NextPayload = decodeMikey[index+2]
	hdr.V_PRFfunc = decodeMikey[index+3]
	copy(hdr.CSB_Id[:], decodeMikey[index+4:index+8])
	hdr.CS = decodeMikey[index+8]
	hdr.CS_Id_MapType = decodeMikey[index+9]
	iMsg.CommonHdr = hdr
	index += 10 // CommonHeader长度

	nextPayload := hdr.NextPayload
	mIdrIndex := 0
	for nextPayload != M_Last {
		if nextPayload == M_T {
			var ts TimeStamp
			ts.NextPayload = decodeMikey[index]
			ts.TsType = decodeMikey[index+1]
			nextPayload = ts.NextPayload
			start := index + 2
			for i := 7; i >= 0; i-- {
				ts.TsValue = ts.TsValue | uint64(decodeMikey[start+i])<<uint64(i*8) // <<优先级高于|
			}
			iMsg.TimStamp = ts
			index += 10
			slog.Infof("Parse Imessage Data TimStamp type TimStamp %+v, nextPayload %+v, index %v", ts, nextPayload, index)
		} else if nextPayload == M_RAND {
			var randPayload RandPayload
			randPayload.NextPayload = decodeMikey[index]
			nextPayload = randPayload.NextPayload
			randPayload.RandLen = decodeMikey[index+1]
			copy(randPayload.Rand[:], decodeMikey[index+2:index+18])
			iMsg.Rand = randPayload
			index += 18
			slog.Infof("Parse Imessage Data Rand type idr %+v, nextPayload %+v, index %v", randPayload, nextPayload, index)
		} else if nextPayload == M_IDR {
			var idr IDRPayload
			idr.NextPayload = decodeMikey[index]
			nextPayload = idr.NextPayload
			idr.IdRole = decodeMikey[index+1]
			idr.IdType = decodeMikey[index+2]
			start := index + 3
			for i := 0; i <= 1; i++ {
				idr.IdLen = (idr.IdLen | uint16(decodeMikey[start+i])) << uint16((1-i)*8)
			}
			idr.IdData = decodeMikey[index+5 : index+5+int(idr.IdLen)]
			//iMsg.IDRs = append(iMsg.IDRs, idr)
			if mIdrIndex == 0 {
				iMsg.IDRi = idr
			} else if mIdrIndex == 1 {
				iMsg.IDRr = idr
			} else if mIdrIndex == 2 {
				iMsg.IDRkmsi = idr
			} else if mIdrIndex == 3 {
				iMsg.IDRkmsr = idr
			}
			mIdrIndex++
			index += 5 + int(idr.IdLen)
			slog.Infof("Parse Imessage Data type idr %+v, nextPayload %+v, index %v", idr, nextPayload, index)
		} else if nextPayload == M_SP {
			var sp SPPayload
			sp.NextPayload = decodeMikey[index]
			nextPayload = sp.NextPayload
			sp.PolicyNo = decodeMikey[index+1]
			sp.ProtType = decodeMikey[index+2]
			copy(sp.PolicyParamLen[:], decodeMikey[index+3:index+5])
			policyParamLen := int(sp.PolicyParamLen[0] << 8)
			policyParamLen |= int(sp.PolicyParamLen[1])
			start := index + 5
			for i := 0; i < policyParamLen; i += 3 {
				var pp PolicyParam
				pp.Type = decodeMikey[start+i]
				pp.Length = decodeMikey[start+i+1]
				pp.Value = decodeMikey[start+i+2]
				sp.PolicyParamSet[i/3] = pp
			}
			iMsg.SP = sp
			index += (5 + policyParamLen)
			slog.Infof("Parse Imessage Data type SP %+v, nextPayload %+v, index %v", sp, nextPayload, index)
		} else if nextPayload == M_SAKKE {
			var sakke SakkePayload
			sakke.NextPayload = decodeMikey[index]
			nextPayload = sakke.NextPayload
			sakke.SakkeParam = decodeMikey[index+1]
			sakke.IdShceme = decodeMikey[index+2]
			start := index + 3
			for i := 0; i <= 1; i++ {
				sakke.SakkeDataLen = (sakke.SakkeDataLen | uint16(decodeMikey[start+i])) << uint16((1-i)*8)
				//slog.Infof("Parse Imessage Data Sakke decodeMikey[start+i] %v", decodeMikey[start+i])
			}
			//slog.Infof("Parse Imessage Data Sakke sakke.SakkeDataLen %v", sakke.SakkeDataLen)
			sakke.SakkeData = decodeMikey[index+5 : index+5+int(sakke.SakkeDataLen)]
			iMsg.Sakke = sakke
			index += 5 + int(sakke.SakkeDataLen)
			slog.Infof("Parse Imessage Data Sakke type Sakke %+v, nextPayload %+v index %v", sakke, nextPayload, index)
		} else if nextPayload == M_GeneralExt { // 组呼秘钥过期时间
			var gep GepPayload
			gep.NextPayload = decodeMikey[index]
			nextPayload = gep.NextPayload
			gep.GepType = decodeMikey[index+1]
			start := index + 2
			for i := 0; i <= 1; i++ {
				gep.GepLen = (gep.GepLen | uint16(decodeMikey[start+i])) << uint16((1-i)*8)
			}
			gep.GepData.KeyType = decodeMikey[index+4]                   // 1 bit
			gep.GepData.Satus = decodeMikey[index+5 : index+9]           // 4 bits
			gep.GepData.ActivationTime = decodeMikey[index+9 : index+14] // 5 bits
			gep.GepData.ExpiryTime = decodeMikey[index+14 : index+19]    // 5 bits
			iMsg.Gep = gep
			index += 19
		} else if nextPayload == M_SIGN { //结束
			signedData = append(signedData, decodeMikey[:index]...)
			var sign SignPayload
			sign.SignType_LenHigh = decodeMikey[index]
			sign.SignLenLow = decodeMikey[index+1]
			sign.Signature = decodeMikey[index+2:]
			iMsg.Sign = sign
			nextPayload = M_Last
			slog.Infof("Parse Imessage Data sign type %v sign %+v, index %v signedData %v", sign, index, signedData)
		} else {
			slog.Error("Parse Imessage Data nextPayload %v error", nextPayload)
		}
	}
	slog.Infof("Parse Imessage Data success iMessage %+v", *iMsg)
	return signedData
}

/* 计算媒体加解密需要的srtp master key 和 srtp master salt
*	The key derivation function defined in section 4.1.4 of IETF RFC 3830 [22]
*	using the PRF-HMAC-SHA-256 Pseudo-Random Function as described in IETF RFC 6043 [25],
*	section 6.1 shall be supported for generating the SRTP Master Key and Salt.
 */
func GenerateKeySalt(SSV []byte, CSB_ID [4]byte, CS_ID byte, RAND [consts.RAND_LEN]byte) ([]byte, []byte) {
	slog.Infof("GenerateKeySalt SSV %v, CSB_ID %v, CS_ID %v, RAND %v", SSV, CSB_ID, CS_ID, RAND)

	//label = Key_Type Constant(4) + CS_ID(1) + CSB_ID(4) + RAND(16).
	keyTypeConstant := [4]byte{0x2A, 0xD0, 0x1C, 0x64} // 0x2AD01C64
	label := keyTypeConstant[:]
	label = append(label, CS_ID)
	label = append(label, CSB_ID[:]...)
	label = append(label, RAND[:]...)
	MasterKey := PRF(SSV, label, len(SSV))

	saltTypeConstant := [4]byte{0x39, 0xA2, 0xC1, 0x4B} //0x39A2C14B
	label = append(saltTypeConstant[:], label[4:]...)
	MasterSalt := PRF(SSV, label, consts.MASTER_SALT_OUT_LEN)

	slog.Infof("GenerateKeySalt MasterKey %v, MasterSalt %v", MasterKey, MasterSalt)

	return MasterKey, MasterSalt
}

/*
	4.1.2. Default PRF Description
	return srtp master key or srtp master salt
*/
func PRF(inKey, label []byte, outKeyLength int) []byte {
	inkey_len := len(inKey)
	n := (inkey_len + consts.PRF_KEY_CHUNK_LENGTH - 1) / consts.PRF_KEY_CHUNK_LENGTH
	m := ( /*outkey_len*/ consts.SHA_DIGEST_SIZE + consts.SHA_DIGEST_SIZE - 1) / consts.SHA_DIGEST_SIZE

	outKey := make([]byte, outKeyLength)
	pOutput := []byte{}
	for i := 0; i < n; i++ {
		if inkey_len <= consts.PRF_KEY_CHUNK_LENGTH {
			pOutput = P(inKey, label, m)
		} else {
			if ((i+1)*consts.PRF_KEY_CHUNK_LENGTH <= inkey_len) {
				pOutput = P(inKey[i*consts.PRF_KEY_CHUNK_LENGTH:(i+1)*consts.PRF_KEY_CHUNK_LENGTH], label, m)
			} else {
				pOutput = P(inKey[i*consts.PRF_KEY_CHUNK_LENGTH:], label, m)
			}
		}

		if i > 0 {
			pOutputLength := len(pOutput)
			if outKeyLength != pOutputLength {
				slog.Error("outKeyLength %v not equal pOutputLength %v", outKeyLength, pOutputLength)
			} else {
				for j := 0; j < outKeyLength; j++ {
					outKey[j] ^= pOutput[j];
				}
			}
		} else {
			copy(outKey, pOutput)
		}
	}
	slog.Infof("PRF outKeyLength %v, inKey %v, label %v, outKey %v", outKeyLength, inKey, label, outKey)
	return outKey
}

/*
	P-function
	4.1.2. Default PRF Description
	P (s, label, m) = HMAC (s, A_1 || label) ||
						HMAC(s, A_2 || label) || ...
						HMAC(s, A_m || label)
*/
func P(s, label []byte, m int) []byte {
	A0 := append([]byte{}, label...) // A0 = label
	A1 := hmacSha256(s, label)       //A1 = HMAC(s,A0)
	tmp := append(A1, A0...)         //HMAC(s, A_1 || label)
	for i := 0; i < m; i++ {
		Ai := hmacSha256(s, tmp) //A_i = HMAC (s, A_(i-1))
		tmp = append(Ai, tmp...)
	}
	return tmp
}

func hmacSha256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	//return hex.EncodeToString(h.Sum(nil)) string
	return h.Sum(nil)
}

/*
*	3.	PUC-MCSGW根据规则生成MS需要的Srtp Master Key以及Srtp Master Salt（根据ICE版本的密钥字符串格式给到MS服务）
*	EncodeKey：（SrtpMasterKey）（SrtpSaltKey）
*	DecodeKey：（SrtpMasterKey）（SrtpSaltKey）
*	媒体要求返回格式为base64格式
 */
func GetCodeKey(SSV []byte, CSB_ID [4]byte, CS_ID byte, RAND [consts.RAND_LEN]byte) []byte {
	masterKey, masterSalt := GenerateKeySalt(SSV, CSB_ID, CS_ID, RAND)
	key := []byte{}
	//key = append(key, byte(len(masterKey)))
	key = append(key, masterKey...)
	//key = append(key, byte(len(masterSalt)))
	key = append(key, masterSalt...)
	return ToBase64(key)
}

// 获取MKI，单呼为32位的PCK-ID，purpose tag置为”1”；组呼为64位，由为GMK-ID || GUK-ID级联组成，purpose tag置为”0”
func GetMki(ssvKey *SSVKeyInfo, msUri string, isGroupCall bool) []byte {
	mki := []byte{}
	if isGroupCall {
		gmkIdBytes := KeyIdToBytes(ssvKey.KeyId)
		gukId := GenerateGUKID(ssvKey, msUri) // 组呼ssvKey的GukId是针对网关账号生成的，所以要根据主被叫重新生成
		mki = append(gmkIdBytes[:], gukId[:]...)
	} else {
		//pckIdBytes := KeyIdToBytes(ssvKey.KeyId)
		//mki = append(mki, pckIdBytes[:]...)
		//mki[0] ^= 0x10
		mki = ssvKey.CSB_Id[:]
	}
	slog.Infof("GetMki len(mki) %v, mki %v, ssvKey %+v", len(mki), mki, ssvKey)
	return mki
}

/*
*	单呼：A的解密秘钥是B的加密秘钥；A的加密秘钥是B的解密秘钥，cs_id取反即可。
 */
func GetCsId(isVideo, isGroupCallType, isInitiate bool) byte {
	var csId byte
	if isGroupCallType {
		if isVideo {
			csId = consts.CS_ID_MCVideo_Group_Call
		} else {
			csId = consts.CS_ID_MCPtt_Group_Call
		}
	} else {
		if isInitiate {
			if isVideo {
				csId = consts.CS_ID_Initiator_MCVideo_Private_Call
			} else {
				csId = consts.CS_ID_Initiator_MCPtt_Private_Call
			}
		} else {
			if isVideo {
				csId = consts.CS_ID_Receiver_MCVideo_Private_Call
			} else {
				csId = consts.CS_ID_Receiver_MCPtt_Private_Call
			}
		}
	}
	return csId
}

// 组呼的CSB-ID为guk-id，单呼的CSB-ID为pck-id
func GenerateCSBID(ssvKeyInfo *SSVKeyInfo, msUri string) [4]byte {
	var csbId [4]byte
	if strings.Index(msUri, "common") != -1 {
		csbId = GenerateGUKID(ssvKeyInfo, msUri)
	} else {
		csbId[0] = byte((ssvKeyInfo.KeyId & 0xff000000) >> 24)
		csbId[1] = byte((ssvKeyInfo.KeyId & 0xff0000) >> 16)
		csbId[2] = byte((ssvKeyInfo.KeyId & 0xff00) >> 8)
		csbId[3] = byte(ssvKeyInfo.KeyId & 0xff)
	}

	return csbId
}

func KeyIdToBytes(id uint32) [4]byte {
	var csbId [4]byte
	csbId[0] = byte((id & 0xff000000) >> 24)
	csbId[1] = byte((id & 0xff0000) >> 16)
	csbId[2] = byte((id & 0xff00) >> 8)
	csbId[3] = byte(id & 0xff)
	return csbId
}

func GetKeyIdByFromCSBID(ssv []byte, csb_id [4]byte, msUri string) uint32 {
	//number, schema := ExtractUserImpu(uri)
	//userUri := "sip:" + number + "@" + service + "." + schema
	var keyId uint32
	if strings.Index(msUri, "common") != -1 { // 网关账号接收并解析组秘钥
		keyId = GetGMKIDByGUKID(ssv, csb_id, msUri)
	} else {
		for i := 3; i >= 0; i-- {
			keyId |= uint32(csb_id[3-i]) << uint32(i*8) // <<优先级高于|
		}
	}

	slog.Infof("get key id from csb id, keyId: %v", keyId)
	return keyId
}
