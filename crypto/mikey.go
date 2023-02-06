/* Desp: 生成mikey和解析mikey
 */

package crypto

import (
	"eccsi_sakke_go/consts"
	//"common/rpc/cc"
	"encoding/hex"
	"errors"
	//"sdk/slog"
	slog "github.com/golang/glog"
	//"time"
)

type MikeyGenMessage struct {
	ReqId    string
	EncType  uint32 // 加密类型
	GrpNum   string // 组号码部分
	Tenant   string // 租户
	PttKey   *SSVKeyInfo
	VideoKey *SSVKeyInfo
	MsSet    []string //	成员列表, impu
}

type SSVKeyInfo struct {
	//Rand    [RAND_LEN]byte 	// 固定长度：16字节	对应Mikey Rand payload
	Rand           [consts.RAND_LEN]byte // 固定长度：16字节	对应Mikey Rand payload
	CSB_Id         [4]byte               // GUK-ID||PCK-ID
	SSV            []byte                // GMK PCK
	SSVLen         uint32                // 字节数
	KeyId          uint32                // GMK-ID/PCK-ID
	GukId          [4]byte               // 组呼才有
	//ServiceType    int                   // 业务类型 1 mcptt 2 mcvideo 3 mcdata
	Entype         consts.EncAlgoType        // 2:128bits aes; 3:256bits aes
	Gep            GepPayload            // 组秘钥生存周期
	InviterMsUri   string                // key的生成者 sip:60000@mcptt.mcs.com
	ResponderMsUri string                // key的接受者 sip:60001@mcptt.mcs.com
}

type GroupTime struct {
	ExpiryTime     int64 `json:"expiry_time"`     //过期时间
	ActivationTime int64 `json:"activation_time"` //生成时间
}

const (
	kms_uri = "kms.example.org"
)

var IsTest bool = false

//msUri eg: "sip:6009755001@mcptt.mcs.com"
func GenerateMikey(ssvKeyInfo *SSVKeyInfo, root *MikeyGenRoot) []byte {
	one := NewIMessage(ssvKeyInfo.SSVLen)
	one.CommonHdr.CSB_Id = GenerateCSBID(ssvKeyInfo, ssvKeyInfo.ResponderMsUri)

	one.Rand.Rand = ssvKeyInfo.Rand
	slog.Infof("SSVKeyInfo len rand: %d, inviterMsUri %s, responderMsUri %s", len(ssvKeyInfo.Rand), ssvKeyInfo.InviterMsUri, ssvKeyInfo.ResponderMsUri)
	one.IDRi.IdData = []byte(ssvKeyInfo.InviterMsUri)
	one.IDRi.IdLen = uint16(len(ssvKeyInfo.InviterMsUri))

	one.IDRr.IdData = []byte(ssvKeyInfo.ResponderMsUri)
	one.IDRr.IdLen = uint16(len(ssvKeyInfo.ResponderMsUri))

	one.IDRkmsi.IdData = []byte(kms_uri)
	one.IDRkmsi.IdLen = uint16(len(kms_uri))

	one.IDRkmsr.IdData = []byte(kms_uri)
	one.IDRkmsr.IdLen = uint16(len(kms_uri))

	uid := GenerateUID(ssvKeyInfo.ResponderMsUri)

	if IsTest { // 测试数据
		uid, _ = hex.DecodeString("323031312D30320074656C3A2B34343737303039303031323300")
		root.UID = uid
	}

	// sakke加密
	sakkeData := SakkeEncrypt(uid, ssvKeyInfo, root)
	sakkeDataLen := len(sakkeData)
	one.Sakke.SakkeData = sakkeData
	one.Sakke.SakkeDataLen = uint16(sakkeDataLen)
	slog.Infof("sakkeDataLen 0x%x", sakkeDataLen)

	res := MakeIMessage(one)

	// eccsi签名
	one.Sign.Signature = EccsiSignature(res, root)
	signLen := len(one.Sign.Signature)
	slog.Infof("signLen 0x%x", signLen)
	one.Sign.SignType_LenHigh = 0x20 + byte((signLen&0xff00)>>8)
	one.Sign.SignLenLow = byte(signLen & 0xff)

	slog.Infof("iMsg: %+v", one)

	res = append(res, one.Sign.SignType_LenHigh)
	res = append(res, one.Sign.SignLenLow)
	res = append(res, one.Sign.Signature...)

	slog.Infof("Generate One Mikey res[%d] %v", len(res), res)

	return ToBase64(res)
}

func GetEntype(iMsg *IMessage) consts.EncAlgoType {
	enType := consts.AlgoAes128
	if 0x20 == iMsg.SP.PolicyParamSet[1].Value { // 不能通过 iMsg.IDRkmsr.NextPayload == M_SP，单呼组呼秘钥这里不统一，单呼sp为默认值
		enType = consts.AlgoAes256
	}
	return enType
}

/***************************************************************************************************
*函数功能： 解析mikey 转成 Imessage格式，提取ssv，校验签名
*参数说明： uriService: sip:60000@mcptt.group.mcs.com, sip:60000@mcvideo.group.mcs.com;
****************************************************************************************************/
func ParseMikey(mikey string, root *MikeyGenRoot) (SSVKeyInfo, error) {
	var key SSVKeyInfo

	if root == nil {
		return key, errors.New("Parse Mikey root nil")
	}

	var iMsg IMessage
	signedData := ParseImessageData(mikey, &iMsg)
	enType := GetEntype(&iMsg)

	slog.Infof("iMsg.Sign.Signature len %v, SignLenLow %v, signedData%v", len(iMsg.Sign.Signature), iMsg.Sign.SignLenLow, signedData)
	slog.Infof("iMsg: %+v", iMsg)
	slog.Infof("Parse Mikey UserUri %s, UriService %s, enType %v, crypto %s", root.UserUri,  root.UserUri, enType, mikey)
	slog.Infof("Parse Mikey sakkeData %s", hex.EncodeToString(iMsg.Sakke.SakkeData))
	slog.Infof("Parse Mikey Signature %s", hex.EncodeToString(iMsg.Sign.Signature))
	slog.Infof("Parse Mikey Initiator %s", string(iMsg.IDRi.IdData))
	slog.Infof("Parse Mikey Responder %s", string(iMsg.IDRr.IdData))

	// 将加密的对称秘钥ssv解析出来
	ssv, err := SakkeDecrypt(iMsg.Sakke.SakkeData, enType, root);
	if err != nil {
		slog.Error("Parse Mikey  root.UserUri %s, Sakke ExtactShareSecret failed err %s",  root.UserUri, err.Error())
		return key, err
	}

	slog.Infof("Parse Mikey root userUri %s SSV %v, crypto %s",  root.UserUri, ssv, mikey)

	if !EccsiVerify(signedData, iMsg.Sign.Signature, GenerateUID(string(iMsg.IDRi.IdData)), root) {
		slog.Error("Eccsi Verify failed groupUriService %s",  root.UserUri)
		return key, errors.New("Eccsi Verify failed")
	}

	//ssvType := consts.GROUP_MCPTT_SSV
	//if strings.Contains(root.UserUri, "mcvideo") {
	//	ssvType = consts.GROUP_MCVIDEO_SSV
	//} else if strings.Contains(root.UserUri, "mcdata") {
	//	ssvType = consts.GROUP_MCDATA_SSV
	//}

	key.SSV = append(key.SSV, ssv...)
	key.SSVLen = uint32(iMsg.SP.PolicyParamSet[1].Value)
	key.Rand = iMsg.Rand.Rand
	key.CSB_Id = iMsg.CommonHdr.CSB_Id
	key.KeyId = GetKeyIdByFromCSBID(ssv, iMsg.CommonHdr.CSB_Id,  root.UserUri)
	key.GukId = iMsg.CommonHdr.CSB_Id
	//key.ServiceType = ssvType
	key.Entype = enType
	key.Gep = iMsg.Gep
	key.InviterMsUri = string(iMsg.IDRi.IdData)
	key.ResponderMsUri = string(iMsg.IDRr.IdData)
	return key, nil
}
