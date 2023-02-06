/* Desp:
 */

package crypto

import "encoding/xml"

// 请求kms的公钥
type KmsInitReq struct {
	XMLName    xml.Name    `xml:"SignedKmsRequest"`
	KmsRequest KmsRequestS `xml:"KmsRequest"`
}

type KmsRequestS struct {
	UserUri string `xml:"UserUri"`
}

// 请求kms的公钥的回应
type KmsInitRes struct {
	SignedKmsResponse xml.Name     `xml:"SignedKmsResponse"`
	KmsResponse       KmsResponseS `xml:"KmsResponse"`
}
type KmsResponseS struct {
	UserUri    string      `xml:"UserUri"`
	Time       string      `xml:"Time"`
	KmsMessage KmsMessageS `xml:"KmsMessage"`
}

type KmsMessageS struct {
	KmsInit    KmsInitS    `xml:"KmsInit"`
	KmsKeyProv KmsKeyProvS `xml:"KmsKeyProv"`
}

type KmsInitS struct {
	KmsCertificate KmsCertificateS `xml:"KmsCertificate"`
}

type KmsCertificateS struct {
	PubEncKey  string `xml:"PubEncKey"` // SAKKE的公共密钥 Z 点 用于 SAKKE 加密发送数据
	PubAuthKey string `xml:"PubAuthKey"` // ECCSI的公共密钥 KPAK 用于ECCSI Sign发送数据
}

// 向kms请求获取用户的加密私钥、签名私钥、eccsi public validation token三个值
type SignedKmsReq struct {
	XMLName    xml.Name    `xml:"SignedKmsRequest"`
	KmsRequest KmsRequestS `xml:"KmsRequest"`
}

//向kms请求获取用户的加密私钥、签名私钥、eccsi public validation token三个值的回应
type SignedKmsRes struct {
	XMLName     xml.Name     `xml:"SignedKmsResponse"`
	KmsResponse KmsResponseS `xml:"KmsResponse"`
}

type KmsKeyProvS struct {
	UserKeysSet []UserKeys `xml:"KmsKeySet"`
}

type UserKeys struct {
	UserUri           string             `xml:"UserUri"`
	UserID            string             `xml:"UserID"`
	UserDecryptKey    UserDecryptKeyS    `xml:"UserDecryptKey"` // 加密私钥
	UserSigningKeySSK UserSigningKeySSKS `xml:"UserSigningKeySSK"`  // 签名私钥
	UserPubTokenPVT   UserPubTokenPVTS   `xml:"UserPubTokenPVT"` // 验签公钥
}

type EncryptedKeyS struct {
	CipherData CipherDataS `xml:"CipherData"`
}

type CipherDataS struct {
	CipherValue string `xml:"CipherValue"`
}

type UserDecryptKeyS struct {
	EncryptedKey EncryptedKeyS `xml:"EncryptedKey"`
}
type UserSigningKeySSKS struct {
	EncryptedKey EncryptedKeyS `xml:"EncryptedKey"`
}
type UserPubTokenPVTS struct {
	EncryptedKey EncryptedKeyS `xml:"EncryptedKey"`
}

type MsUriMikey struct{
	MsUri string // sip:xxx@mcptt.group.xxx.xxx or sip:xxx@mcvideo.group.xxx.xxx
	Mikey string // base64格式
}