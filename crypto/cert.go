/* Desp:
 */

package crypto

// Tips: 参数解读
// 除字段UserUri外，其他几个字段都是协议参数 数值类型的16进制字符串，即字符串的每两个字符 对应 参数数值的一个字节
// 字段UserID，正确解读: 88 36 9A A3 7F 5B 41 A0 1F D3 7A 51 92 30 58 89 6B 6E 5A 3F 3D 08 2E 54 5C D4 2E D6 4D 7B EB CD
// 数据来源：mcs
var CCTest4 = &CertCache {
	PubEncKey:"04286462369dc569e1870466b954272f615817ae1d2b3860516d2c6e9366a9b838bf2fe4883292b883878990471f9fc333362526c7e39d7860907d7f3f003df4e8da0a6b76245f7d120d2735e83967375d50d0a40211138f7302284fc91422c7e63a42cb4dac4b03d57f5439d9139fbd6f33298dacf942b09cb498bb130fe1a1a22d1994c2bb91189a20d5b00d7ec5eb68f1b26ea10b3001fce2ae8f48ef13f3b5b5340d65e233846abb9d2a91caaeb7ce49f582f32d49e55821cc04bed4c388b413939f0e88b13e3e482341147eb869fdb2811333f4c157663cf1ef54a2bc3edfd534e5f262d3267b8a55f88e82b63dcd209039112f8f30b6d28435760632bcdb",
	PubAuthKey:"0440b5f8f5b45078282c96f66c8000a8dbf19e0031d7ffd9cb6e2a10f120fb2d0292e559894cd2f2959bbf97874e9c0a8ca98148e62c0b3fd5d3009070ec8300d9",
	UserUri:"sip:60030208@mcvideo.common.com",
	UserID:"F9A0A43CB9D2586BF7BEE63B31966270E027952928C2C5BE4E4D92BAEF0492D7",
	UserDecryptKey:"042cc883f7dcedf8613bfb544cfa559c1ed3a060ddc3015e232d21ed26c35433309234071ebaa65c19883dd6231fbc4937ddae58e56ef148a90da325ce2ceeea222133109179642ee9b595af759d9fc056fcdcb788995717ef606b26a9796368903ae8b092b50cf836627ba15189e52be892a3f4c9ff8c37e586dd1cdf47d6abb358add9dc3b1750c65c33f5713c5c311c0df47f395381b94ebb9e754a34a7254829d4b5ef3ebd534a1c946ddfc81f8b954e35397651d6ae15ee3548ded2a27c93368300fa5d39239be904a1345745007d577ae3558ed6d5a17d769c1bea304ec017a6f337866b9fc4e013919ada8c5b9432eef5d1d5e4105c8e2183073e06a4a5",
	UserSigningKeySSK:"0000c15fd0c2605466db2e7839272e5b87799423a35c2fb65cdc7e5e68d67fe72510",
	UserPubTokenPVT:"047f1ca855f883a7ca5eefc4b45dc863046ad42f7f503a124d29edbf4d4f5f578217d99a1dd4799caf252493b1ef799d7855a7faa2c2c78874a66d3363649d4ee5",
}

// 数据来源：mcs
var CCTest5 = &CertCache {
	PubEncKey:"04286462369dc569e1870466b954272f615817ae1d2b3860516d2c6e9366a9b838bf2fe4883292b883878990471f9fc333362526c7e39d7860907d7f3f003df4e8da0a6b76245f7d120d2735e83967375d50d0a40211138f7302284fc91422c7e63a42cb4dac4b03d57f5439d9139fbd6f33298dacf942b09cb498bb130fe1a1a22d1994c2bb91189a20d5b00d7ec5eb68f1b26ea10b3001fce2ae8f48ef13f3b5b5340d65e233846abb9d2a91caaeb7ce49f582f32d49e55821cc04bed4c388b413939f0e88b13e3e482341147eb869fdb2811333f4c157663cf1ef54a2bc3edfd534e5f262d3267b8a55f88e82b63dcd209039112f8f30b6d28435760632bcdb",
	PubAuthKey:"0440b5f8f5b45078282c96f66c8000a8dbf19e0031d7ffd9cb6e2a10f120fb2d0292e559894cd2f2959bbf97874e9c0a8ca98148e62c0b3fd5d3009070ec8300d9",
	UserUri:"sip:4245037@mcptt.common.com",
	UserID:"C21CE15C2061C384E576DB9B6AA8CF22CFC53060AC8F5993D8E092307FD8BE4D",
	UserDecryptKey:"04853645b73ff9a5252c8454114c428b11e61240a508396fbdcf3a7702ac0819222c8d929ccb7d699be8da61a3a16431d4857c491d6c27fc8fad71866de5ccdfa9bbd0c8ae0168f6b86fd437eded87424f8eb84ecb9f84bcabb3d2f919eb131306bed65b78907eb1b755333be27f3a222e61b509df7705b0f93d1e458809ccbc2e8628cf3e29eeb25d8115a45ac8e9236fbbf75a70653d1de03b0d070866b66f01d90f7c1185e5a12dc9044afa74607e07a366debb5779e27e943b395a39dad032d985a51cbdae5574756d8d997150784a4bc93012ba6cbf67b3c4f787a11247013ba4c3b350ea734a7b49409c2387c5e83776f3896dd7165861ff7d362b65145f",
	UserSigningKeySSK:"000043a18acdbac58818d29b0f2bf3839a1df131fb4140a15688daad11fbf817c600",
	UserPubTokenPVT:"04257d5bab9a509297cd0e0489d872e53a3db32f0885b6d31ad1ae3214b8f21553f91f07f74ae11221a7bc2d0a772957212442a3300173c1338d2b4bdff6a35e06",
}

var CC *CertCache

/*
// 从Init应答中提取出的关键字段
type Certificate struct {
	PubEncKey 	string      //RFC6508中描述的SAKKE的公共密钥, "Z_T",. 用来描述椭圆曲线上的一个点的8位字节串（eg：029A2F）
	PubAuthKey 	string     	//RFC6507中描述的ECCSI 公共密钥 "KPAK". 用来描述椭圆曲线上的一个点的8位字节串（eg：029A2F）
}

// 初始化从KMS获取到的证书和密钥材料
func InitCertCache(cert *Certificate, km *KeyMaterial) {
	slog.Info("init CertCache.")

	cc := CertCache{}
	// 由KMS证书 m_cert 获取数据
	cc.PubEncKey = cert.PubEncKey              //[RFC6508] SAKKE KMS公钥 Z_T
	cc.PubAuthKey = cert.PubAuthKey            //[RFC6507] ECCSI 公钥 KPAK

	// 由KMS密钥材料 m_key 获取数据
	cc.UserUri = km.UserUri
	cc.UserID = km.UserID
	cc.UserDecryptKey = km.UserDecryptKey     	//[RFC6508] SAKKE RSK
	cc.UserSigningKeySSK = km.UserSigningKeySSK  //[RFC6507] ECCSI SSK
	cc.UserPubTokenPVT = km.UserPubTokenPVT	   	//[RFC6507] ECCSI PVT

	slog.Info("PubEncKey[%d] %s", len(cc.PubEncKey), cc.PubEncKey)
	slog.Info("PubAuthKey[%d] %s", len(cc.PubAuthKey), cc.PubAuthKey)

	slog.Info("UserUri[%d] %s", len(cc.UserUri), cc.UserUri)
	slog.Info("UserID[%d] %s", len(cc.UserID), cc.UserID)
	slog.Info("UserDecryptKey[%d] %s", len(cc.UserDecryptKey), cc.UserDecryptKey)
	slog.Info("UserSigningKeySSK[%d] %s", len(cc.UserSigningKeySSK), cc.UserSigningKeySSK)
	slog.Info("UserPubTokenPVT[%d] %s", len(cc.UserPubTokenPVT), cc.UserPubTokenPVT)

	CC = &cc
}
*/

type CertCache struct {
	PubEncKey 		string		//RFC6508中描述的SAKKE公共密钥"Z_T" 用来描述椭圆曲线上的一个点的8位字节串
	PubAuthKey 		string		//RFC6507中描述的ECCSI公共密钥"KPAK" 用来描述椭圆曲线上的一个点的8位字节串

	UserUri 			string	//这批密钥的使用者的URI
	UserID 				string	//密钥对应的UID
	UserDecryptKey 		string	//RFC6508中描述的SAKKE RSK 用来描述椭圆曲线上的一个点的8位字节串
	UserSigningKeySSK 	string	//RFC6507中描述的ECCSI 私钥"SSK" 描述一个整数的8位字节串，用于eccsi 签名发送数据
	UserPubTokenPVT 	string	//RFC6507中描述的ECCSI 令牌"PVT" 用来描述椭圆曲线上的一个点的8位字节串, 用于eccsi 签名发送数据
}