/* Desp:
 */

package crypto

import (
	"eccsi_sakke_go/consts"
	//"sdk/slog"
	slog "github.com/golang/glog"
	"time"
)

// Tips: !!! 代码注释说明，I_MESSAGE字段定义优先查阅[BWT-3800V18B_MCS 端到端加密方案设计说明书]，详细介绍参见标注的RFC文档

// NextPayloda: 0-12,20-21在RFC3830定义；13-17在RFC6043定义；26在RFC6509定义；

/*******************************************************************************
* 功能说明： 定义Mikey消息结构体 I_MESSAGE
* 设计文档： [BWT-3800V18B_MCS 端到端加密方案设计说明书][16.7.1 I_MESSAGE]
* 参见文档： Mikey结构 [RFC6509][2.1. Outline]
*******************************************************************************/

// I_MESSAGE = HDR, T, RAND, [IDRi], [IDRr], [IDRkmsi], [IDRkmsr], [CERT], {SP}, SAKKE, SIGN
type IMessage struct {
	CommonHdr CommonHeader // HDR,10
	TimStamp  TimeStamp    // Timestamp,10
	Rand      RandPayload  // Rand,18
	//IDRs      []IDRPayload // IDRi + IDRr + kmsi + kmsr
	IDRi      IDRPayload   // IDRi(Initiator),35
	IDRr      IDRPayload   // IDRr(Responder),35
	IDRkmsi   IDRPayload   // kmsi(Initiator),35
	IDRkmsr   IDRPayload   // kmsr(Responder),35
	SP        SPPayload    // SP
	Sakke     SakkePayload // SAKKE,9
	Sign      SignPayload  // SIGN,6
	Gep       GepPayload   // 3GPP Params
}

/*******************************************************************************
* 功能说明：3GPP
* 参见文档： RAND组成	[RFC3830][6.11. RAND payload (RAND)]
*******************************************************************************/
type GepPayload struct {
	NextPayload byte
	GepType     byte    //3gpp  key parameters 取 7
	GepLen      uint16  //扩展数据长度
	GepData     GepData //只取Key_Type(0),Satus(0),Activation_Time,Expiry_Time
}

type GepData struct {
	KeyType        byte
	Satus          []byte
	ActivationTime []byte
	ExpiryTime     []byte
}

/*******************************************************************************
* 功能说明： HDR 消息头
* 参见文档： HDR组成	[RFC3830][6.1. Common Header payload (HDR)]
                  	[RFC6509][4.1. Common Header Payload (HDR)]
					[RFC6043][6.1. Common Header Payload (HDR)]
*******************************************************************************/
type CommonHeader struct {
	Version       byte
	DataType      byte
	NextPayload   byte
	V_PRFfunc     byte
	CSB_Id        [4]byte // GUK-ID||PCK-ID
	CS            byte
	CS_Id_MapType byte
}

/*******************************************************************************
* 功能说明： T 时间戳
* 参见文档： T组成	[RFC3830][6.6. Timestamp payload (T)]
*******************************************************************************/
type TimeStamp struct {
	NextPayload byte
	TsType      byte
	TsValue     uint64
}

/*******************************************************************************
* 功能说明： RAND 随机数
* 参见文档： RAND组成	[RFC3830][6.11. RAND payload (RAND)]
*******************************************************************************/
type RandPayload struct {
	NextPayload byte
	RandLen     byte
	Rand        [consts.RAND_LEN]byte // 随机数，所有组成员收到的值是相同的；协议要求至少16字节，编码以固定16字节实现
}

/*******************************************************************************
* 功能说明： IDR
* 参见文档： IDR组成	[RFC6043][6.6. ID Payload with Role Indicator (IDR)]
					[RFC6509][4.4. IDR Payload]
*******************************************************************************/
type IDRPayload struct {
	NextPayload byte
	IdRole      byte
	IdType      byte
	IdLen       uint16
	IdData      []byte
}

/*******************************************************************************
* 功能说明： SP 安全协议
* 参见文档： IDR组成	[RFC3830][6.10. Security Policy payload (SP)]
					[RFC3830][6.10.1. SRTP policy]
*******************************************************************************/
type SPPayload struct {
	NextPayload    byte
	PolicyNo       byte
	ProtType       byte
	PolicyParamLen [2]byte
	PolicyParamSet [10]PolicyParam // The Policy param part is built up by a set of Type/Length/Value fields
}

// ProtType固定赋值0 即默认采用SRTP, 因此 PolicyParam 定义的是SRTP安全协议的策略参数
type PolicyParam struct {
	Type   byte
	Length byte
	Value  byte
}

/*******************************************************************************
* 功能说明： SAKKE
* 参见文档： SAKKE组成	[RFC6509][4.2. SAKKE Payload]
						[RFC6508][6.2.1. Sender]
*******************************************************************************/
type SakkePayload struct {
	NextPayload  byte
	SakkeParam   byte
	IdShceme     byte
	SakkeDataLen uint16
	SakkeData    []byte // 生成算法参见 [RFC6508][6.2.1. Sender]; [4. Representation of Values]描述其长度: 2*L + n + 1
}

/*******************************************************************************
* 功能说明： SIGN
* 参见文档： SIGN组成	[RFC3830][6.5. Signature payload (SIGN)]
					[RFC6507][5.2.1. Algorithm for Signing]
*******************************************************************************/
type SignPayload struct {
	SignType_LenHigh byte
	SignLenLow       byte
	Signature        []byte // 生成算法参见 [RFC6507][5.2.1. Algorithm for Signing]; Tips: 编码实现字节长度固定 0x81=129
}

func NewIMessage(ssvLen uint32) *IMessage {
	res := &IMessage{}

	res.CommonHdr.Version = 1
	res.CommonHdr.DataType = 26
	res.CommonHdr.NextPayload = M_T
	res.CommonHdr.V_PRFfunc = 2 // PRF func:7bit V:1bit = 0000 001 0
	// res.CommonHdr.CSB_Id
	res.CommonHdr.CS = 0
	res.CommonHdr.CS_Id_MapType = 1

	res.TimStamp.NextPayload = M_RAND
	res.TimStamp.TsType = 0
	res.TimStamp.TsValue = uint64(time.Now().Unix())

	res.Rand.NextPayload = M_IDR
	res.Rand.RandLen = consts.RAND_LEN
	// res.Rand.Rand

	res.IDRi.NextPayload = M_IDR
	res.IDRi.IdRole = 1
	res.IDRi.IdType = 1
	// res.IDRi.IdLen
	// res.IDRi.IdData

	res.IDRr.NextPayload = M_IDR
	res.IDRr.IdRole = 2
	res.IDRr.IdType = 1
	// res.IDRr.IdLen
	// res.IDRr.IdData

	res.IDRkmsi.NextPayload = M_IDR
	res.IDRkmsi.IdRole = 3
	res.IDRkmsi.IdType = 1
	// res.IDRkmsi.IdLen
	// res.IDRkmsi.IdData

	res.IDRkmsr.NextPayload = M_SAKKE
	res.IDRkmsr.IdRole = 3
	res.IDRkmsr.IdType = 1
	// res.IDRkmsr.IdLen
	// res.IDRkmsr.IdData

	if ssvLen == 0x20 { // bits 256才有sp
		res.IDRkmsr.NextPayload = M_SP

		res.SP.NextPayload = M_SAKKE
		res.SP.PolicyNo = 1
		res.SP.ProtType = 0 // SRTP
		res.SP.PolicyParamLen[0] = 0
		res.SP.PolicyParamLen[1] = 30

		res.SP.PolicyParamSet[0].Type = 0 // todo-yyl: 策略参数取值的出处在哪里？   试试看  端到端 16.7.2.2	GENERIC-ID Map
		res.SP.PolicyParamSet[0].Length = 1
		res.SP.PolicyParamSet[0].Value = 6
		res.SP.PolicyParamSet[1].Type = 1
		res.SP.PolicyParamSet[1].Length = 1
		res.SP.PolicyParamSet[1].Value = byte(ssvLen)
		res.SP.PolicyParamSet[2].Type = 2
		res.SP.PolicyParamSet[2].Length = 1
		res.SP.PolicyParamSet[2].Value = 4
		res.SP.PolicyParamSet[3].Type = 4
		res.SP.PolicyParamSet[3].Length = 1
		res.SP.PolicyParamSet[3].Value = 12
		res.SP.PolicyParamSet[4].Type = 5
		res.SP.PolicyParamSet[4].Length = 1
		res.SP.PolicyParamSet[4].Value = 0
		res.SP.PolicyParamSet[5].Type = 6
		res.SP.PolicyParamSet[5].Length = 1
		res.SP.PolicyParamSet[5].Value = 0
		res.SP.PolicyParamSet[6].Type = 13
		res.SP.PolicyParamSet[6].Length = 1
		res.SP.PolicyParamSet[6].Value = 1
		res.SP.PolicyParamSet[7].Type = 18
		res.SP.PolicyParamSet[7].Length = 1
		res.SP.PolicyParamSet[7].Value = 4
		res.SP.PolicyParamSet[8].Type = 19
		res.SP.PolicyParamSet[8].Length = 1
		res.SP.PolicyParamSet[8].Value = 0
		res.SP.PolicyParamSet[9].Type = 20
		res.SP.PolicyParamSet[9].Length = 1
		res.SP.PolicyParamSet[9].Value = 16
	}

	res.Sakke.NextPayload = M_SIGN
	res.Sakke.SakkeParam = 1
	res.Sakke.IdShceme = 2
	// res.Sakke.SakkeDataLen
	// res.Sakke.SakkeData

	// res.Sign.SignType_LenHigh
	// res.Sign.SignLenLow
	// res.Sign.Signature

	return res
}

func MakeIMessage(msg *IMessage) []byte {
	msglen := CalcNonAlignedSizeOfIMessage(msg)
	slog.Infof("msglen %d", msglen)
	// 由于结构体包含切片类型字段，因此 msglen肯定小于结构体实际引用的字节数，此处只为减少底层数组的扩张次数
	res := make([]byte, 0, msglen)

	slog.Infof("IDRi.IdLen[0x%x] IDRr.IdLen[0x%x] IDRkmsi_IdLen[0x%x] IDRkmsr_IdLen[0x%x] Sakke.SakkeDataLen[0x%x]",
		msg.IDRi.IdLen, msg.IDRr.IdLen, msg.IDRkmsi.IdLen, msg.IDRkmsr.IdLen, msg.Sakke.SakkeDataLen)

	res = append(res, msg.CommonHdr.Version, msg.CommonHdr.DataType,
		msg.CommonHdr.NextPayload, msg.CommonHdr.V_PRFfunc)
	res = append(res, msg.CommonHdr.CSB_Id[:]...)
	res = append(res, msg.CommonHdr.CS, msg.CommonHdr.CS_Id_MapType)

	res = append(res, msg.TimStamp.NextPayload, msg.TimStamp.TsType)
	timsstamp := make([]byte, 8)
	timsstamp[0] = byte(msg.TimStamp.TsValue & 0x00000000000000FF)
	timsstamp[1] = byte((msg.TimStamp.TsValue & 0x000000000000FF00) >> 8)
	timsstamp[2] = byte((msg.TimStamp.TsValue & 0x0000000000FF0000) >> 16)
	timsstamp[3] = byte((msg.TimStamp.TsValue & 0x00000000FF000000) >> 24)
	timsstamp[4] = byte((msg.TimStamp.TsValue & 0x000000FF00000000) >> 32)
	timsstamp[5] = byte((msg.TimStamp.TsValue & 0x0000FF0000000000) >> 40)
	timsstamp[6] = byte((msg.TimStamp.TsValue & 0x00FF000000000000) >> 48)
	timsstamp[7] = byte((msg.TimStamp.TsValue & 0xFF00000000000000) >> 56)
	res = append(res, timsstamp...)

	res = append(res, msg.Rand.NextPayload, msg.Rand.RandLen)
	res = append(res, msg.Rand.Rand[:]...)

	idlen := make([]byte, 2)

	res = append(res, msg.IDRi.NextPayload, msg.IDRi.IdRole, msg.IDRi.IdType)
	idlen[0] = byte((msg.IDRi.IdLen & 0xFF00) >> 8)
	idlen[1] = byte(msg.IDRi.IdLen & 0x00FF)
	res = append(res, idlen...)
	res = append(res, msg.IDRi.IdData[:]...)

	res = append(res, msg.IDRr.NextPayload, msg.IDRr.IdRole, msg.IDRr.IdType)
	idlen[0] = byte((msg.IDRr.IdLen & 0xFF00) >> 8)
	idlen[1] = byte(msg.IDRr.IdLen & 0x00FF)
	res = append(res, idlen...)
	res = append(res, msg.IDRr.IdData[:]...)

	res = append(res, msg.IDRkmsi.NextPayload, msg.IDRkmsi.IdRole, msg.IDRkmsi.IdType)
	idlen[0] = byte((msg.IDRkmsi.IdLen & 0xFF00) >> 8)
	idlen[1] = byte(msg.IDRkmsi.IdLen & 0x00FF)

	res = append(res, idlen...)
	res = append(res, msg.IDRkmsi.IdData[:]...)

	res = append(res, msg.IDRkmsr.NextPayload, msg.IDRkmsr.IdRole, msg.IDRkmsr.IdType)
	idlen[0] = byte((msg.IDRkmsr.IdLen & 0xFF00) >> 8)
	idlen[1] = byte(msg.IDRkmsr.IdLen & 0x00FF)
	res = append(res, idlen...)
	res = append(res, msg.IDRkmsr.IdData[:]...)

	if msg.IDRkmsr.NextPayload == M_SP {//aes_128bits has not SecurityPolicy
		res = append(res, msg.SP.NextPayload, msg.SP.PolicyNo, msg.SP.ProtType)
		res = append(res, msg.SP.PolicyParamLen[:]...)
		for i := 0; i < len(msg.SP.PolicyParamSet); i++ {
			res = append(res, msg.SP.PolicyParamSet[i].Type, msg.SP.PolicyParamSet[i].Length, msg.SP.PolicyParamSet[i].Value)
		}
	}

	res = append(res, msg.Sakke.NextPayload, msg.Sakke.SakkeParam, msg.Sakke.IdShceme)
	idlen[0] = byte((msg.Sakke.SakkeDataLen & 0xFF00) >> 8)
	idlen[1] = byte(msg.Sakke.SakkeDataLen & 0x00FF)
	res = append(res, idlen...)
	res = append(res, msg.Sakke.SakkeData...)

	slog.Infof("res %d", len(res))
	return res
}

// Tips: 使用unsafe.Sizeof获取结构体大小 是字节对齐的长度
func CalcNonAlignedSizeOfIMessage(msg *IMessage) uint16 {
	msglen := 10 + 10 + 18 +
		(5 + msg.IDRi.IdLen) + (5 + msg.IDRr.IdLen) +
		(5 + msg.IDRkmsi.IdLen) + (5 + msg.IDRkmsr.IdLen) +
		(5 + msg.Sakke.SakkeDataLen)

	if msg.IDRkmsr.NextPayload == M_SP { // 256 bits ssv has sp
		msglen += 35
	}

	// 或 逐个字段 获取字节数
	//msglen = unsafe.Sizeof(msg.CommonHdr.Version)
	//msglen += unsafe.Sizeof(msg.CommonHdr.DataType)
	//msglen += unsafe.Sizeof(msg.CommonHdr.NextPayload)
	//msglen += unsafe.Sizeof(msg.CommonHdr.V_PRFfunc)
	//msglen += unsafe.Sizeof(msg.CommonHdr.CSB_Id)
	//msglen += unsafe.Sizeof(msg.CommonHdr.CS)
	//msglen += unsafe.Sizeof(msg.CommonHdr.CS_Id_MapType)
	//
	//msglen += unsafe.Sizeof(msg.TimStamp.NextPayload)
	//msglen += unsafe.Sizeof(msg.TimStamp.TsType)
	//msglen += unsafe.Sizeof(msg.TimStamp.TsValue)

	return msglen
}
