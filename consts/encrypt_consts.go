package consts

// aes对称加密类型
const (
	AES_NULL int = 0 // 不加密
	AES_128  int = 1
	AES_256  int = 2
)

// aes ssv bit长度
const (
	AES_128_BITS int = 128 // 128位加密长度
	AES_256_BITS int = 256 // 256位加密长度
)

// 固定长度：16字节	对应Mikey Rand payload
const MIKEY_RAND_LEN = 16

// 不同业务的组呼对称秘钥类型
const (
	GROUP_MCPTT_SSV   int = 1
	GROUP_MCVIDEO_SSV int = 2
	GROUP_MCDATA_SSV  int = 3
)

//参考TS33.180 E.1.3； 用于标识MIKEY中秘钥的用途；此字段不在MIKEY中携带，在生成SRTP/SRTCP时使用
const (
	CS_ID_Initiator_MCPtt_Private_Call       byte = 0x00
	CS_ID_Receiver_MCPtt_Private_Call        byte = 0x01
	CS_ID_Initiator_MCVideo_Private_Call     byte = 0x02
	CS_ID_Receiver_MCVideo_Private_Call      byte = 0x03
	CS_ID_MCPtt_Group_Call                   byte = 0x04
	CS_ID_MCVideo_Group_Call                 byte = 0x05
	CS_ID_CSK_SRTCP_protection_for_MCPtt     byte = 0x06
	CS_ID_MuSiK_SRTCP_protection_for_MCPtt   byte = 0x07
	CS_ID_CSK_SRTCP_protection_for_MCVideo   byte = 0x08
	CS_ID_MuSiK_SRTCP_protection_for_MCVideo byte = 0x09
)

/*
   数据来源 rfc3830 4.1.3
   constant    | derived key from the TGK
   --------------------------------------
   0x2AD01C64  | TEK
   0x1B5C7973  | authentication key
   0x15798CEF  | encryption key
   0x39A2C14B  | salting key
*/

//const (
//	Key_Label_Constant  = [4]byte{0x2A, 0xD0, 0x1C, 0x64} // 0x2AD01C64
//	Salt_Label_Constant = [4]byte{0x39, 0xA2, 0xC1, 0x4B}  //0x39A2C14B
//)

//TODO： 这里应该除8换算成字节？
const (
	PRF_KEY_CHUNK_LENGTH = 256 // serves as define to split inkey in 256 bit chunks；
	SHA_DIGEST_SIZE      = 160 // 160 bit of SHA1 take 20 bytes
)

const (
	MASTER_KEY_OUT_LEN  = 16 // 128 bits master key 16 bytes
	MASTER_SALT_OUT_LEN = 12 // 96 bits master salt 12 bytes
)


const RAND_LEN = 16

const (
	Not_Encrypt_Call = iota
	Is_Encrypt_Call
)

// crypto type
type EncAlgoType int
const (
	AlgoNull EncAlgoType = iota
	AlgoArc4
	AlgoAes128
	AlgoAes256
)