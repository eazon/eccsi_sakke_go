/* Desp:
 */

package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	//"sdk/slog"
	slog "github.com/golang/glog"
	"strings"
)

type EC_POINT struct {
	X *big.Int
	Y *big.Int
}

//Root is for test
var Root = &MikeyGenRoot{
	bInitOK: false,
}

type MikeyGenRoot struct {
	EncKeyZ_S EC_POINT // Sakke加密：KMS公钥Z_S，参与对GMK的加密（用户公钥也参与GMK的加密）
	KPAK      []byte   // RFC6507中描述的ECCSI公共密钥"KPAK" 用来描述椭圆曲线上的一个点的8位字节串, 即PubAuthKey
	RSK       EC_POINT // Sakke加密：KMS为GMS生成的私钥RSK
	UID       []byte   // GMS的 MIKEY-SAKKE-UID
	HS        []byte   // Eccsi签名：由(G || KPAK || ID || PVT)哈希计算得到，在给Imessage签名和验证签名时需要用到
	PVT       []byte   // Eccsi签名：KMS为GMS生成的PVT rfc6507 5.1 pvt为验签公钥
	SSK       *big.Int // Eccsi签名：KMS为GMS生成的SSK rfc6507 5.1 SSK为签名私钥
	UserUri   string   // sip:6009755001@mcptt.mcs.com
	bInitOK   bool     // 标识以上参数是否完成初始化
}

//Compute HS = hash( G || KPAK || ID || PVT ), an N-octet integer. The integer HS SHOULD be stored with the SSK for later use;
//KPAK kms 签名公钥
func ComputeHs(UID, KPAK, PVT []byte) []byte {
	// G||KPAK||ID||PVT 并非字符串拼接，而是各参数数值类型的字节序列 组合
	GByteNum := 1 + len(EccsiEC.Param_Gx.Bytes()) + len(EccsiEC.Param_Gy.Bytes())
	G := make([]byte, 0, GByteNum)
	G = append(G, 0x04)
	G = append(G, EccsiEC.Param_Gx.Bytes()...)
	G = append(G, EccsiEC.Param_Gy.Bytes()...)
	//slog.Infof("G[%d] %v", len(G), G)

	//KPAK, _ := hex.DecodeString(PubAuthKey)
	//slog.Infof("KPAK[%d] %v", len(KPAK), KPAK)

	G_KPAK_ID_PVT := make([]byte, 0, len(G)+len(KPAK)+len(UID)+len(PVT))
	G_KPAK_ID_PVT = append(G_KPAK_ID_PVT, G...)
	G_KPAK_ID_PVT = append(G_KPAK_ID_PVT, KPAK...)
	G_KPAK_ID_PVT = append(G_KPAK_ID_PVT, UID...)
	G_KPAK_ID_PVT = append(G_KPAK_ID_PVT, PVT...)

	//G_KPAK_ID_PVT = []byte("0x046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F50450D4670BDE75244F28D2838A0D25558A7A72686D4522D4C8273FB6442AEBFA93DBDD37551AFD263B5DFD617F3960C65A8C298850FF99F20366DCE7D4367217F4323031312D30320074656C3A2B3434373730303930303132330004758A142779BE89E829E71984CB40EF758CC4AD775FC5B9A3E1C8ED52F6FA36D9A79D247692F4EDA3A6BDAB77D6AA6474A464AE4934663C5265BA7018BA091F79")
	//slog

	hash := sha256.New()
	hash.Write(G_KPAK_ID_PVT)
	return hash.Sum(nil)
}

/*******************************************************************************
* 功能说明： 初始化Sakke加密和Eccsi签名参数, 校验SSK
* 输入参数：	从KMS请求到的证书和密钥材料
*******************************************************************************/
func (root *MikeyGenRoot) InitMikeyGenRoot(crt *CertCache) {
	slog.Infof("InitMikeyGenRoot crt: %+v", *crt)
	/************************************** Eccsi **************************************/
	// [RFC6507][5.1.2. Algorithm for Validating a Received SSK]
	// Every SSK MUST be validated before being installed as a signing key.
	// 1) Validate that the PVT lies on the elliptic curve E;
	root.PVT, _ = hex.DecodeString(crt.UserPubTokenPVT)
	slog.Infof("Init Mikey Gen Root UserUri %s root.PVT[%d] %v", crt.UserUri, len(root.PVT), root.PVT)

	eccsiXYBytes := (len(root.PVT) - 1) / 2 // len-1 表示去掉前缀字节 0x04
	if eccsiXYBytes != ECCSI_XY_BYTES {
		slog.Warning("eccsiXYBytes[%d] != %d", eccsiXYBytes, ECCSI_XY_BYTES)
	}

	PVTx := new(big.Int).SetBytes(root.PVT[1 : eccsiXYBytes+1])
	PVTy := new(big.Int).SetBytes(root.PVT[eccsiXYBytes+1:])
	if bOn := EccsiEC.IsOnCurve(PVTx, PVTy); bOn {
		slog.Infof("(PVTx, PVTy) is on Eccsi Curve.")
	} else {
		slog.Fatal("(PVTx, PVTy) is not on Eccsi Curve.")
	}

	// 2) Compute HS = hash( G || KPAK || ID || PVT ), an N-octet integer. The integer HS SHOULD be stored with the SSK for later use;
	// G||KPAK||ID||PVT 并非字符串拼接，而是各参数数值类型的字节序列 组合
	/***GByteNum := 1 + len(EccsiEC.Param_Gx.Bytes()) + len(EccsiEC.Param_Gy.Bytes())
	G := make([]byte, 0, GByteNum)
	G = append(G, 0x04)
	G = append(G, EccsiEC.Param_Gx.Bytes()...)
	G = append(G, EccsiEC.Param_Gy.Bytes()...)
	slog.Infof("G[%d] %v", len(G), G)**/

	KPAK, _ := hex.DecodeString(crt.PubAuthKey)
	root.KPAK = KPAK
	slog.Infof("KPAK[%d] %v", len(KPAK), KPAK)

	root.UserUri = crt.UserUri
	ID := GenerateUID(crt.UserUri) // "sip:10000@mcptt.mcs.com"
	if crt.UserID != strings.ToUpper(hex.EncodeToString(ID)) {
		slog.Errorf("ID != %s", crt.UserID)
	} else {
		root.UID = ID
		slog.Infof("root.UID[%d] %v", len(root.UID), strings.ToUpper(hex.EncodeToString(ID)))
	}

	if IsTest { // 测试
		uid, _ := hex.DecodeString("323031312D30320074656C3A2B34343737303039303031323300")
		root.UID = uid
	}

	/***G_KPAK_ID_PVT := make([]byte, 0, len(G)+len(KPAK)+len(root.UID)+len(root.PVT))
	G_KPAK_ID_PVT = append(G_KPAK_ID_PVT, G...)
	G_KPAK_ID_PVT = append(G_KPAK_ID_PVT, KPAK...)
	G_KPAK_ID_PVT = append(G_KPAK_ID_PVT, root.UID...)
	G_KPAK_ID_PVT = append(G_KPAK_ID_PVT, root.PVT...)

	hash := sha256.New()
	hash.Write(G_KPAK_ID_PVT)
	root.HS = hash.Sum(nil)***/
	root.HS = ComputeHs(root.UID, root.KPAK, root.PVT)
	slog.Infof("HS[%d] %s", len(root.HS), hex.EncodeToString(root.HS))

	//3) Validate that KPAK = [SSK]G - [HS]PVT.  等价验证 KPAK + [HS]PVT = [SSK]G
	HS_PVT_ProductX, HS_PVT_ProductY := EccsiEC.ScalarMult(PVTx, PVTy, root.HS)

	eccsiXYBytes = (len(KPAK) - 1) / 2
	if eccsiXYBytes != ECCSI_XY_BYTES {
		slog.Warning("eccsiXYBytes[%d] != %d", eccsiXYBytes, ECCSI_XY_BYTES)
	}
	KPAKx := new(big.Int).SetBytes(KPAK[1 : eccsiXYBytes+1])
	KPAKy := new(big.Int).SetBytes(KPAK[eccsiXYBytes+1:])
	resX, resY := EccsiEC.Add(KPAKx, KPAKy, HS_PVT_ProductX, HS_PVT_ProductY)

	root.SSK, _ = new(big.Int).SetString(crt.UserSigningKeySSK, 16)
	SSK_G_ProductX, SSK_G_ProductY := EccsiEC.ScalarBaseMult(root.SSK.Bytes())
	if 0 == SSK_G_ProductX.Cmp(resX) && 0 == SSK_G_ProductY.Cmp(resY) {
		slog.Infof("KPAK == [SSK]G - [HS]PVT")
	} else {
		slog.Error("KPAK != [SSK]G - [HS]PVT")
	}
	// Tips: 如下先对big.Int取负数再做加法 实际上并不能等同于 椭圆曲线上的减法；由于椭圆曲线未提供减法，因此可采用如上的等价验证
	//HS_PVT_ProductX = HS_PVT_ProductX.Neg(HS_PVT_ProductX)
	//HS_PVT_ProductY = HS_PVT_ProductY.Neg(HS_PVT_ProductY)
	//resX, resY = EccsiEC.Add(SSK_G_ProductX, SSK_G_ProductY, HS_PVT_ProductX, HS_PVT_ProductY)
	//if 0==KPAKx.Cmp(resX) && 0==KPAKy.Cmp(resY) {
	//	slog.Infof("KPAK == [SSK]G - [HS]PVT")
	//} else {
	//	slog.Error("KPAK != [SSK]G - [HS]PVT")
	//}

	/************************************** Sakke **************************************/
	Z_T, _ := hex.DecodeString(crt.PubEncKey) // 16进制字符串 转化为 byte切片（两个字符对应一个byte）
	sakkeXYBytes := (len(Z_T) - 1) / 2        // len-1 表示去掉前缀字节 0x04
	if sakkeXYBytes != SAKKE_XY_BYTES {
		slog.Warning("sakkeXYBytes[%d] != %d", sakkeXYBytes, SAKKE_XY_BYTES)
	}

	Z_Tx := new(big.Int).SetBytes(Z_T[1 : sakkeXYBytes+1]) // Tips: [1:128]  128是下标，目的元素的下个索引值
	Z_Ty := new(big.Int).SetBytes(Z_T[sakkeXYBytes+1:])
	slog.Infof("Z_Tx[%d] %v", len(Z_Tx.Bytes()), Z_Tx.Bytes())
	slog.Infof("Z_Ty[%d] %v", len(Z_Ty.Bytes()), Z_Ty.Bytes())
	if bok := SakkeEC.IsOnCurve(Z_Tx, Z_Ty); bok {
		slog.Infof("(Z_Tx, Z_Ty) is on Sakke Curve.")

	} else {
		slog.Fatal("(Z_Tx, Z_Ty) is not on Sakke Curve.")
	}
	root.EncKeyZ_S.X = Z_Tx
	root.EncKeyZ_S.Y = Z_Ty

	RSK, _ := hex.DecodeString(crt.UserDecryptKey)
	sakkeXYBytes = (len(RSK) - 1) / 2 // len-1 表示去掉前缀字节 0x04
	if sakkeXYBytes != SAKKE_XY_BYTES {
		slog.Warning("sakkeXYBytes[%d] != %d", sakkeXYBytes, SAKKE_XY_BYTES)
	}
	RSKx := new(big.Int).SetBytes(RSK[1 : sakkeXYBytes+1])
	RSKy := new(big.Int).SetBytes(RSK[sakkeXYBytes+1:])
	slog.Infof("RSKx[%d] %v", len(RSKx.Bytes()), RSKx.Bytes())
	slog.Infof("RSKy[%d] %v", len(RSKy.Bytes()), RSKy.Bytes())
	if bok := SakkeEC.IsOnCurve(RSKx, RSKy); bok {
		slog.Infof("(RSKx, RSKy) is on Sakke Curve.")

	} else {
		slog.Error("(RSKx, RSKy) is not on Sakke Curve.")
	}
	root.RSK.X = RSKx
	root.RSK.Y = RSKy

	// 初始化完成
	root.bInitOK = true
}
