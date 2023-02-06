package crypto

import (
	"bytes"
	"encoding/base64"
)

/*// 将16进制字符串 转换为 数值字节序列
// 303132 --> 30 31 32
// 0x30 0x31 0x32
func TwoCharToEachByte(in []byte) []byte {
	i := 0
	inLen := len(in)

	outLen := inLen >> 1
	out := make([]byte, outLen)
	for j := 0; j < outLen; j++ {
		if 47 < in[i] && 58 > in[i] { // [48, 57] 即 '0'~'9'
			out[j] = (in[i] - 48) * 16

		} else if 96 < in[i] && 123 > in[i] { // [97, 122] 即 'a'~'z'
			out[j] = (in[i] - 87) * 16

		} else if 64 < in[i] && 91 > in[i] { // [65, 90] 即 'A'~'Z'
			out[j] = (in[i] - 55) * 16 // 减55的目的是为了得到 16进制A B C D E F对应的10进制数值10 11 12 13 14 15

		} else {
			return nil
		}
		i++

		if 47 < in[i] && 58 > in[i] { // [48, 57] 即 '0'~'9'
			out[j] += in[i] - 48

		} else if 96 < in[i] && 123 > in[i] { // [97, 122] 即 'a'~'z'
			out[j] += in[i] - 87

		} else if 64 < in[i] && 91 > in[i] { // [65, 90] 即 'A'~'Z'
			out[j] += in[i] - 55

		} else {
			return nil
		}
		i++ // 之前算法有误，是由于此处漏掉 i++
	}

	return out
}

// IntToBytes 将int类型的数转化为字节并以小端存储
// eg: 0x2AD01C64 ==> [100 28 208 42]
func IntToBytes(intNum int) []byte {
	uint16Num := uint16(intNum)
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, uint16Num)
	return buf.Bytes()
}*/

func ToBase64(src []byte) []byte{
	bb := &bytes.Buffer{}
	encoder := base64.NewEncoder(base64.StdEncoding, bb)
	encoder.Write(src)
	//result := bb.Bytes()
	//slog.Info("before bb %v", bb.Bytes())
	encoder.Close()
	//slog.Info("after bb %v", bb.Bytes())
	return bb.Bytes()
}

//func ExChangeEncryType(encType cc.EncAlgoType) (encTypeMS ms.EncAlgoTypeMs) {
//	switch encType {
//	case cc.AlgoArc4:
//		return ms.AlgoArc4
//	case cc.AlgoAes128:
//		return ms.AlgoAes128
//	case cc.AlgoAes256:
//		return ms.AlgoAes256
//	}
//	return ms.AlgoNull
//}

/*//根据用户号码获取数字和域名。sip:600001@mcs.com。获取数字：600001，域名：mcs.com
//返回第一个值为数字，第二个值为域名
func ExtractUserImpu(impu string) (string, string) {
	var number, schema string

	if len(impu) == 0 {
		slog.Error("user impu is empty.")
		return "", ""
	}

	if bOk := strings.Contains(impu, "@"); !bOk {
		return impu, ""
	} else {
		tmpslice := strings.Split(impu, "@")
		number = tmpslice[0]
		if idslice := strings.Split(number, "sip:"); len(idslice) > 1 {
			number = idslice[1]
		}

		schema = tmpslice[1]
		return number, schema
	}
}

// 一个字节 转换成 两个可见字符
func EachByteToTwoChar(in []byte) []byte {
	if in == nil || len(in) == 0 {
		return nil
	}

	out := make([]byte, 2*len(in))
	j := 0

	for i := 0; i < len(in); i++ {
		mid := in[i] >> 4 // 高4位
		out[j] = ToLetterNumber(mid)
		j++

		mid = in[i] & 0x0f // 低4位
		out[j] = ToLetterNumber(mid)
		j++
	}

	return out
}

// 将4bit数值(取值范围[0, 15]) 转换成ASCII码中的 字母 或 数字
// b在[0, 9] 转化为 '0'~'9'
// b在(9, 15] 转化为 'A'~'F'
func ToLetterNumber(b byte) byte {
	if 9 < b {
		return b + 55 // b + '7'

	} else {
		return b + 48 // b + '0'
	}
}*/