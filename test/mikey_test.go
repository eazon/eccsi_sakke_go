package test

import (
	"eccsi_sakke_go/crypto"
	"encoding/base64"
	"flag"
	"io/ioutil"
	//"sdk/slog"
	slog "github.com/golang/glog"
	"strings"
	"testing"
)

// 秘钥数据来源： rfc6507 Appendix A. Test Data
func Test_GenerateOneMikey(t *testing.T) {
	crypto.IsTest = true
	ssvKeyInfo := crypto.MakeSSVKey(2, false) //128
	//ssvKeyInfo = crypto.MakeSSVKey(3, false)//256
	msUri := "sip:6009755001@mcptt.mcs.com"
	ssvKeyInfo.InviterMsUri = msUri
	ssvKeyInfo.ResponderMsUri = msUri
	crypto.InitSakkeAndEccsi()
	//uid, _ := hex.DecodeString("323031312D30320074656C3A2B34343737303039303031323300")
	//crypto.Root.UID = uid
	crypto.Root.InitMikeyGenRoot(crypto.CCTest2)
	mikeyx := crypto.GenerateMikey(ssvKeyInfo, crypto.Root)
	slog.Infof("mikey %v ", string(mikeyx))
	// base64解码
	//bb := &bytes.Buffer{}
	//bb.Write(crypto)
	reader := strings.NewReader(string(mikeyx))
	decoder := base64.NewDecoder(base64.StdEncoding, reader)
	//decoder.Read(crypto)
	decoded, _ := ioutil.ReadAll(decoder)

	slog.Infof("mikey decode %v ", decoded)

	//crypto 解析
	crypto.ParseMikey(string(mikeyx), crypto.Root)
}

// 秘钥数据来源：kms gms
func Test_GenerateOneMikey1(t *testing.T) {
	flag.Set("alsologtostderr", "true") // Log printing to terminal and file
	ssvKeyInfo := crypto.MakeSSVKey(2, false)//128
	//ssvKeyInfo := crypto.MakeSSVKey(3, false) //256
	ssvKeyInfo.InviterMsUri = crypto.CCTest4.UserUri
	ssvKeyInfo.ResponderMsUri = crypto.CCTest4.UserUri
	crypto.InitSakkeAndEccsi()

	//crypto.Root.InitMikeyGenRoot(crypto.CCTest3)
	//mikeyx := crypto.GenerateOneMikey(ssvKeyInfo, crypto.CCTest3.UserUri, crypto.Root)

	crypto.Root.InitMikeyGenRoot(crypto.CCTest4)
	mikeyx := crypto.GenerateMikey(ssvKeyInfo, crypto.Root)
	slog.Infof("zz ssv: %v ", ssvKeyInfo.SSV)
	slog.Infof("mikey %v ", string(mikeyx))

	// base64解码
	//bb := &bytes.Buffer{}
	//bb.Write(crypto)
	/*reader := strings.NewReader(string(mikeyx))
	decoder := base64.NewDecoder(base64.StdEncoding, reader)
	//decoder.Read(crypto)
	decoded, _ := ioutil.ReadAll(decoder)
	slog.Infof("crypto decode %v ", decoded)*/

	//crypto 解析
	crypto.ParseMikey(string(mikeyx), crypto.Root)
}


// 秘钥和mikey数据来源：kms gms
func Test_ParseMikey(t *testing.T) {
	crypto.InitSakkeAndEccsi()
	crypto.Root.InitMikeyGenRoot(crypto.CCTest5) //mcptt
	//crypto.Root.InitMikeyGenRoot(crypto.CCTest4)//mcvideo

	// mcptt crypto
	//mikeyx := "ARoFAgSN588AAQsAY1dWYwAAAAAOEKDHzvalCeweIabG15nkYOgOAQEAEXNpcDpnbXNAbWNwdHQuY29tDgIBAB1zaXA6NjAwMzAyMDhAbWNwdHQuY29tbW9uLmNvbQ4DAQAPa21zLmV4YW1wbGUub3JnCgMBAA9rbXMuZXhhbXBsZS5vcmcaAQAAHgABBgEBEAIBBAQBDAUBAAYBAA0BARIBBBMBABQBEBUBAgERBEGCEMX9kJGKx2OUBvQolusa4G8t0ASHmyi95+kkorag9tA4GtKuybsz/sVio3PwZ7bT7msYy6VzIhPOEa6Xd7lY8GH3RO6E5p6vROJv6b+s5sMu05GRJ9A5hmKeG7APHBNYIpOyJX6d8hf1sWK4s8AncyV7mGr1n0dmfK5Rw+grNPSZgU6n2DEIuJn0XTa16jktt2J86TRNQJbBUjtpCue8Ep7KVhcMfeh2xNVmZ2oPy6GTE7PvTvEBAI3qybUAtvszGf8EJJ9/PE+/uI9aWO4N+yXKpTQQH1BdXCawM0vetYQlkVxzvYrIoohs/aZ9UojxL67NdILxSSZ5dqEcsiaUzVq/9Bak3y8Y9DPd05DOBAcADwAAAAABAGUsqhEAZwdGESCBaFsqb4XamPGtMCafq1BOxSypN9vt3USEknuCGyBGf1gz//tWs70Ks16nyo4GCkAj162QdBtrmTY7zNKzaw7khwQuF4KmF7po82XnVqHMDKmE5R6mdzeZoFeXfwe/Zu80ZaIqERW9njSBHCbpkNL2oMHLtgWO/+eP9abB0eKYapfr"
	//mikeyx := "ARoFAR/jFJwAAQsA5wNxfAAAAAAOEO6oP0VBQ1bDZ3mMaljU2msOAQEAGHNpcDo3NzcwMDFAbWNwdHQubWNzLmNvbQ4CAQAYc2lwOjc3NzAwMkBtY3B0dC5tY3MuY29tDgYBAA9rbXMuZXhhbXBsZS5vcmcaBwEAD2ttcy5leGFtcGxlLm9yZwQBAgERBHYOFvfZPsI/8zNKWEVLUAhVVqUFLxr9IxLOdu/U/f+iNYNhluFg6H4WbSJwYCMX9inz1OQf6f78NPzLstAJ5jY8A06Lw/Mmwt2X5JjP96/NouAdOvAlqcQvj+fJmUzM/6t94qIt0AQQ28KaYt9U4OpPk2lVG+ZUA9JKSWZ5+dTWWCPjkHcnuBqTVn3rnwAm0DpSIBlONGVJPs1dp8lJnuK4FSl607JztSgkowHmEq2RJRv/lnClcm0ddrI9VS/AgE1ggvSyMhV4RUHxMsjUBk0pd7FKaHfA3fxecHBSXlvM1zozA/62ScVVHMMYkDKfOGh3sRF7Seo0b3/GqQYRAkIDjLWD78p4GB9+eQDdcnxJIIHmTauHCpiNeUiJqdlcdvtr5+Oa2Lg0oHeVn96Vc+egDTkG9Q4nNoBF5AdDQllx+blCnc0DE9YCZp7bQWu5qqS7BOHE+LJHpeaJhgv9DIr9f6MO/uQhB6tqxxMMJ5znaYqgVouJNnGUPQw4mlL1XSJQQCQBxAO5VV/0AaDCDh8ZLBQ="
	//mikeyx3 := "ARoFAR2ahpMAAQsA5wSooAAAAAAOEJD9yncxcnIm6RCWZPDbgAUOAQEAGHNpcDo3NzcwMDFAbWNwdHQubWNzLmNvbQ4CAQAdc2lwOjYwMDMwMjA4QG1jcHR0LmNvbW1vbi5jb20OBgEAD2ttcy5leGFtcGxlLm9yZxoHAQAPa21zLmV4YW1wbGUub3JnBAECAREERH812aCNi/vvQfNeWfkpp5ipH911XkxrjFiDnJRj9lqP42bLaKVFJRoKKmIof5HaoUGuulmR9ju4Djs2uh2IGy2J8rmKfuKxNxwuylppQZQpXgyaxP66vkUedBTvTt8P/j6ACjbl3W4oBWwaRP5nathZVLG0q+GdIHYRIFzGk7YmHxV5Zjla/c6SApnpe8DHLfn+vEYgVnL5r5Oa3IwfADLT2Zbqm1BlTcdU+NfIoAza0gOCcPyfonxByyNnO6QqmAP5AvS6IhiY+Rn1M7nUUB3V+Dj0uSb3WbmY3gi09yGHURnTmOaxLMb93nHqw5+bqOTTJCeQf4Lwh0rso9xKYQC5h7Y1lwVTO+D5d0gtnskggXcswB+anBNVVw+ixfLs3hcu0BCJ5N6U1p98ejeCES5bbhAbG2qPp5q6l03Lc5EF3RFRdECpGiS/M0oQNW6WLAUE7ikYgtN3HbYBhw/on1QTWlQ5aPvUIXTVoMMVt3CdLcM9RNi8ovHhZYi89Dno2OHVRrw7WFjZWO/gtVxLuWZsfA=="

	mikeyX := "ARoFARTJn2oAAQsA5wyVBwAAAAAOEEw1kfRC/Q3iUk+H7A3ZWzsOAQEAFnNpcDo1MDAyQG1jcHR0Lm1jcy5jb20OAgEAHHNpcDo0MjQ1MDM3QG1jcHR0LmNvbW1vbi5jb20OBgEAD2ttcy5leGFtcGxlLm9yZxoHAQAPa21zLmV4YW1wbGUub3JnBAECAREEjY+Pjm/Qasn1m21eX5tfphrwtLYL48TDq2Eo4G5HigSQKCEQn5nkZTS9V84oMeHXum50SAJnxtbn52Yg5U8/E5Deyg6n7isWeWWCaPlL8yXyupGvtNykHBvsiCKhpMmdMfn3/pQfV81e3pkwQyKOJkU3D1IDZY51+0ymDuLSPoIUmIRDE0h8VCrnSfQIusGbnIyn3MALO+k0uVrGSDfxnsaJxasp7zCeXjTiktoJ8suFEuL0kBvnvwIbS9KJAp3KBTXw8UwYRa/NQvXrWT8XpEd+yiWW5MV3iCEGqY8Pz6F+x6BdJlB25CST7xidaFu3GVgkSPrmnNN5RGuHK1WdahGwD1BjZDdJzdD1TJ5NhNQggWkHkbp70YJfcgtzNPJW6qkDXBmppaB4MzXr5/qYyZsrWGof6uFW4X16jp0DnM71xsIn2fhxmB3uUDJZgrnY3CkEBVTcAfmALAvq/IM7VD2jWILsp55GxPaaKPAjsbmwOUMlSXVwgnOBTwMMAoQtcoz7IcQ9GRfChgyBHayJXLT0NQ=="
	//mikeyX = "ARoFAgdUMPsAAQsAlxl/YwAAAAAOEHO9Eb59FTHN+bQRhmiAyY0OAQEAEXNpcDpnbXNAbWNwdHQuY29tDgIBAB5zaXA6NDI0NTAzN0BtY3ZpZGVvLmNvbW1vbi5jb20OAwEAD2ttcy5leGFtcGxlLm9yZwoDAQAPa21zLmV4YW1wbGUub3JnGgEAAB4AAQYBARACAQQEAQwFAQAGAQANAQESAQQTAQAUARAVAQIBEQRkMC/ApVp24e0IG/pqGoof/KJBViT8x1BE/qpO1C+wdpkjfpvIVFs0WjHG7sRH6fdgRmN7myUfzp8RBfjWAp4pYP+yu+vtnkI7NupELEevX9+33bi7qzjHc/u0OB+7g7WCyvv3/5hESeKfMllUQlsSVyO5cBuaYjlmA+CFfv6ONVWgHQ4MSyNkzbD3VI4SRd9sCKENdhbIy1C8MUInaVygTnCoBvjY3isiDkBCygBvgP4OZC+e0K3eglQ7BaZ69GEQH45ZYHjQAfgPZb0jyGjh9z3DC1C0HUbj8ffhGc0aiB9yFtoJC/KDZXbkJ2gVfOm7r9eezHe1c+WMjEDvXS8HiVbm3q72JmhVsCg9I2CoEQQHAA8AAAAAAQBjfxmQAG6ewZAggZLBVcn0fCI4R3xIkAFFtgwhaktDF5vO2Cn9X7wtWtrdKp8L96FBJHCu/V4ZyxCWLkksXhwk7KyOXAfCbC6NSqIEkwyxfxnB7oOzOSJiBjO/Q/xQrx+XrvP5j3Mv52HnQ+NUdr3ShG8KPVzNOIZQ5uYL7P2vyiBZiZtIuxTceT3tog=="
	mikeyX = "ARoFAgmCTcIAAQsA0iV/YwAAAAAOELRDKgjdKecIeDoWcl1vyxEOAQEAEXNpcDpnbXNAbWNwdHQuY29tDgIBABxzaXA6NDI0NTAzN0BtY3B0dC5jb21tb24uY29tDgMBAA9rbXMuZXhhbXBsZS5vcmcKAwEAD2ttcy5leGFtcGxlLm9yZxoBAAAeAAEGAQEgAgEEBAEMBQEABgEADQEBEgEEEwEAFAEQFQECASEEVssRpgOG3AYwuPLT0ujWdmfQ+rXhY8YjQS9AuuueSJaP/GB6obBxrvl4HxUZsbSzJOv3IoGnN/sY9H/ZXMWAC8MKS+l23bB1VWdxBBBdosDY+sCXSiqKDL9T5KdjVFUrBNd+aC/p23ViJyk087iaJJLF763mJTsSgwp3mNOy1/N+Kkwz3SnHLqUp6DB+6zurk5cHPYmvlvb2AVMGHynmWNcyydY5oa0HMatNoPMgZABvByvzdDZw9J6dO3jzroGe/EhTJig/gedNx+SA3Wnv2VS4mIJN13+m+7631UOOo3oyVT8tvh4+x6LFqZpqvZ6ki0C/63Rx+FUiKY3vNutZmWN3KDxWS85zbc2nTwgMxHcodtfsKhmOLgnezM650HM/BAcADwAAAAABAGN/Jc0Abp7NzSCBuiYusMrPDGIxocppA9JT+1XOJJIjQSDg4HL9an6ZaBORT5c3ODmhlXGrUmdEzmTgjXf+Kmfc47i4Dg4eSLhAwgSTDLF/GcHug7M5ImIGM79D/FCvH5eu8/mPcy/nYedD41R2vdKEbwo9XM04hlDm5gvs/a/KIFmJm0i7FNx5Pe2i"
	mikeyX = "ARoFAgMzPkEAAQsASC5/YwAAAAAOEIEdEUvRjpFmo82vDlHSDt0OAQEAEXNpcDpnbXNAbWNwdHQuY29tDgIBABxzaXA6NDI0NTAzN0BtY3B0dC5jb21tb24uY29tDgMBAA9rbXMuZXhhbXBsZS5vcmcKAwEAD2ttcy5leGFtcGxlLm9yZxoBAAAeAAEGAQEQAgEEBAEMBQEABgEADQEBEgEEEwEAFAEQFQECAREEc/wUw3th1Xj323tEllyhZ3elqbNXiPtycktCgId0dCxL731UUGrmHwATmqmfHjtCm7n/JyOeZtr0LoE/5oSLXE7NeS1zJvdEe0O6m+3DiYuQpXSgyvrSAo9zthcVNmIDE1T3JoyZWMmQWDCtVuBa4b1SgbiACA9C9M+fS4dDaIs6cKQ3mg1J/JMHRDaBcv5SSctorU3wPyDoNIET6PxOjjELA6Pe50PbdhsZDkTYNuh2GZi/uH8ErxAo2BN05tEiKbAUn4CBGcH4akn+dM9mc8jsoBlcTNggYUjJidAAh0pi/LBjOzEdcmObHdDGn3uPMZqX+x92d2rkkEtthFEkA/ChvzvQFaoL1aD3Ku9yXooEBwAPAAAAAAEAY38uRQBuntZFIIHOTm+qk0XoJtQWjzGBVNf4YoImCUrctNbyBWqZNhZF/Edp40thhpT4Cb4sgp+hDLXdzBhzOYIjYN7wDEIuy3NPBJMMsX8Zwe6DszkiYgYzv0P8UK8fl67z+Y9zL+dh50PjVHa90oRvCj1czTiGUObmC+z9r8ogWYmbSLsU3Hk97aI="
	crypto.ParseMikey(string(mikeyX), crypto.Root)
}