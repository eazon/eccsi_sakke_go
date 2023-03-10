/* Desp:
 */

package crypto

// Eccsi签名曲线参数 同标准库 elliptic.P256，详见p256_asm.go
/****************************************************************************
* [RFC6507][Appendix A. Test Data]
* This appendix provides test data built from the NIST P-256 curve and
* base point. SHA-256 (as defined in [FIPS180-3]) is used as the hash
* function.
****************************************************************************/
const (
	ECCSI_p = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
	/* [RFC6507][Appendix A. Test Data] p 椭圆曲线模数p */

	ECCSI_q = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
	/* [RFC6507][Appendix A. Test Data] q */

	ECCSI_B = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
	/* [RFC6507][Appendix A. Test Data] B 椭圆曲线参数b */

	ECCSI_Gx = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
	ECCSI_Gy = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
	/* [RFC6507][Appendix A. Test Data] G 的 x, y 坐标*/

	ECCSI_G = "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
	/* [RFC6507][Appendix A. Test Data] G 椭圆曲线基准点 由 04||Gx||Gy 拼接得到 */

)

// Sakke加密曲线参数
/****************************************************************************
* [RFC6509][Appendix A. Parameters for Use in MIKEY-SAKKE]
* [RFC6508] requires each application to define the set of public
* parameters to be used by implementations. Parameter Set 1 is defined
* in this appendix. Descriptions of the parameters are provided in
* Section 2.1 of [RFC6508].
****************************************************************************/
const (
	SAKKE_p = "997ABB1F0A563FDA65C61198DAD0657A416C0CE19CB48261BE9AE358B3E01A2EF40AAB27E2FC0F1B228730D531A59CB0E791B39FF7C88A19356D27F4A666A6D0E26C6487326B4CD4512AC5CD65681CE1B6AFF4A831852A82A7CF3C521C3C09AA9F94D6AF56971F1FFCE3E82389857DB080C5DF10AC7ACE87666D807AFEA85FEB"
	/* [RFC6509][Appendix A. Parameters for Use in MIKEY-SAKKE] p */

	SAKKE_q = "265EAEC7C2958FF69971846636B4195E905B0338672D20986FA6B8D62CF8068BBD02AAC9F8BF03C6C8A1CC354C69672C39E46CE7FDF222864D5B49FD2999A9B4389B1921CC9AD335144AB173595A07386DABFD2A0C614AA0A9F3CF14870F026AA7E535ABD5A5C7C7FF38FA08E2615F6C203177C42B1EB3A1D99B601EBFAA17FB"
	/* [RFC6509][Appendix A. Parameters for Use in MIKEY-SAKKE] q */

	SAKKE_B = "0"
	/* [RFC6508] 由椭圆曲线方程 y² = x³ - 3x modulo p 确定 */

	SAKKE_Px = "53FC09EE332C29AD0A7990053ED9B52A2B1A2FD60AEC69C698B2F204B6FF7CBFB5EDB6C0F6CE2308AB10DB9030B09E1043D5F22CDB9DFA55718BD9E7406CE8909760AF765DD5BCCB337C86548B72F2E1A702C3397A60DE74A7C1514DBA66910DD5CFB4CC80728D87EE9163A5B63F73EC80EC46C4967E0979880DC8ABEAE63895"
	/* [RFC6509][Appendix A. Parameters for Use in MIKEY-SAKKE] Px */

	SAKKE_Py = "0A8249063F6009F1F9F1F0533634A135D3E82016029906963D778D821E141178F5EA69F4654EC2B9E7F7F5E5F0DE55F66B598CCF9A140B2E416CFF0CA9E032B970DAE117AD547C6CCAD696B5B7652FE0AC6F1E80164AA989492D979FC5A4D5F213515AD7E9CB99A980BDAD5AD5BB4636ADB9B5706A67DCDE75573FD71BEF16D7"
	/* [RFC6509][Appendix A. Parameters for Use in MIKEY-SAKKE] Py */

	SAKKE_g = "66FC2A432B6EA392148F15867D623068C6A87BD1FB94C41E27FABE658E015A87371E94744C96FEDA449AE9563F8BC446CBFDA85D5D00EF577072DA8F541721BEEE0FAED1828EAB90B99DFB0138C7843355DF0460B4A9FD74B4F1A32BCAFA1FFAD682C033A7942BCCE3720F20B9B7B0403C8CAE87B7A0042ACDE0FAB36461EA46"
	/* [RFC6509][Appendix A. Parameters for Use in MIKEY-SAKKE] g */
)
