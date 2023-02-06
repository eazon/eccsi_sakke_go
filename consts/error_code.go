package consts

const (
	//用于rpc应答中的成功、失败
	RspCodeSuccess int = iota
	RspCodeFailure
)

const (
	CauseCodeGwMcsErrStart int = 5600000

	CauseCodeGwMcsErrCommUnmarshalJsonTlv int = 5611001 // rpc反序列化失败
	CauseCodeGwMcsErrCommMarshalJsonTlv   int = 5611002 // rpc序列化失败
	CauseCodeGwMcsErrCommUnmarshalJson    int = 5611003 // json反序列化失败
	CauseCodeGwMcsErrCommMarshalJson      int = 5611004 // json序列化失败
	CauseCodeGwMcsErrCmdNameWrong         int = 5611009 // cmd_name错误
	CauseCodeGwMcsErrSapNotExist          int = 5611010 // sap不存在
	CauseCodeGwMcsErrSapNotRegister       int = 5611011 // sap未注册
	CauseCodeGwMcsErrSapHasNoCallMgr      int = 5611012 // sap不存在call模块
	CauseCodeGwMcsErrUnknowError          int = 5611014 // 未知错误

	CauseCodeGwMcsErrRequestMissingField int = 5612001 // 请求缺少必要字段

	CauseCodeGwMcsErrDgnaCreateError int = 5613001 // 动态组创建失败
	CauseCodeGwMcsErrDgnaDeleteError int = 5613002 // 动态组删除失败
	CauseCodeGwMcsErrDgnaUpdateError int = 5613003 // 动态组更新失败
	CauseCodeGwMcsErrDgnaAddMemError int = 5613004 // 动态组添加成员失败
	CauseCodeGwMcsErrDgnaDelMemError int = 5613005 // 动态组删除成员失败

	CauseCodeGwMcsErrSysPatchCreateError int = 5613101 // 系统派接组创建失败
	CauseCodeGwMcsErrSysPatchDeleteError int = 5613102 // 系统派接组删除失败
	CauseCodeGwMcsErrSysPatchUpdateError int = 5613103 // 系统派接组更新失败
	CauseCodeGwMcsErrSysPatchAddMemError int = 5613104 // 系统派接组添加成员失败
	CauseCodeGwMcsErrSysPatchDelMemError int = 5613105 // 系统派接组删除成员失败

	CauseCodeGwMcsErrMonMcpttError   int = 5613201 // 语音业务监听失败
	CauseCodeGwMcsErrMonMcvideoError int = 5613202 // 视频业务监听失败
	CauseCodeGwMcsErrMonMcdataError  int = 5613203 // 数据业务监听失败

	CauseCodeGwMcsErrStunError   int = 5613301 // 遥晕失败
	CauseCodeGwMcsErrReviveError int = 5613302 // 复活失败
	CauseCodeGwMcsErrKillError   int = 5613303 // 遥毙失败

	CauseCodeGwMcsErrFloorDenyReason    uint32 = 5614000
	CauseCodeGwMcsErrFloorDenyReason1   int    = 5614001 // Another MCPTT user has permission
	CauseCodeGwMcsErrFloorDenyReason2   int    = 5614002 // Internal floor control server error
	CauseCodeGwMcsErrFloorDenyReason3   int    = 5614003 // Only one participant
	CauseCodeGwMcsErrFloorDenyReason4   int    = 5614004 // Retry-after timer has not expired
	CauseCodeGwMcsErrFloorDenyReason5   int    = 5614005 // Receive only
	CauseCodeGwMcsErrFloorDenyReason6   int    = 5614006 // No resources available
	CauseCodeGwMcsErrFloorDenyReason7   int    = 5614007 // Queue full
	CauseCodeGwMcsErrFloorDenyReason255 int    = 5614255 // Other reason, the floor control server does not grant the floor request due to the floor control server local policy

	CauseCodeGwGroupCryptoKeyNotFoundError int    = 5615001 // 加密组呼，未找到对应组秘钥
)

var CauseCodeErrDesc = map[int]string{

	CauseCodeGwMcsErrCommUnmarshalJsonTlv: "unmarshal json tlv msg error", // rpc反序列化失败
	CauseCodeGwMcsErrCommMarshalJsonTlv:   "marshal json tlv msg error",   // rpc序列化失败
	CauseCodeGwMcsErrCommUnmarshalJson:    "unmarshal json msg error",     // json反序列化失败
	CauseCodeGwMcsErrCommMarshalJson:      "marshal json msg error",       // json序列化失败
	CauseCodeGwMcsErrCmdNameWrong:         "cmd name wrong",               // cmd_name错误
	CauseCodeGwMcsErrSapNotExist:          "sap not exist",                // sap不存在
	CauseCodeGwMcsErrSapNotRegister:       "sap not register",             // sap未注册
	CauseCodeGwMcsErrSapHasNoCallMgr:      "sap has no call mgr",          // sap不存在call模块
	CauseCodeGwMcsErrUnknowError:          "unknown error",                // 未知错误

	CauseCodeGwMcsErrRequestMissingField: "request missing field", // 请求缺少必要字段

	CauseCodeGwMcsErrDgnaCreateError: "dgna create failed",     // 动态组创建失败
	CauseCodeGwMcsErrDgnaDeleteError: "dgna delete failed",     // 动态组删除失败
	CauseCodeGwMcsErrDgnaUpdateError: "dgna update failed",     // 动态组更新失败
	CauseCodeGwMcsErrDgnaAddMemError: "dgna add member failed", // 动态组添加成员失败
	CauseCodeGwMcsErrDgnaDelMemError: "dgna del member failed", // 动态组删除成员失败

	CauseCodeGwMcsErrSysPatchCreateError: "system patch group create failed",     // 系统派接组创建失败
	CauseCodeGwMcsErrSysPatchDeleteError: "system patch group delete failed",     // 系统派接组删除失败
	CauseCodeGwMcsErrSysPatchUpdateError: "system patch group update failed",     // 系统派接组更新失败
	CauseCodeGwMcsErrSysPatchAddMemError: "system patch group add member failed", // 系统派接组添加成员失败
	CauseCodeGwMcsErrSysPatchDelMemError: "system patch group del member failed", // 系统派接组删除成员失败

	CauseCodeGwMcsErrMonMcpttError:   "monitor mcptt service failed",   // 语音业务监听失败
	CauseCodeGwMcsErrMonMcvideoError: "monitor mcvideo service failed", // 视频业务监听失败
	CauseCodeGwMcsErrMonMcdataError:  "monitor mcdata service failed",  // 数据业务监听失败

	CauseCodeGwMcsErrStunError:   "stun failed",   // 遥晕失败
	CauseCodeGwMcsErrReviveError: "revive failed", // 复活失败
	CauseCodeGwMcsErrKillError:   "kill failed",   // 遥毙失败

	CauseCodeGwMcsErrFloorDenyReason1:   "Another MCPTT user has permission",
	CauseCodeGwMcsErrFloorDenyReason2:   "Internal floor control server error",
	CauseCodeGwMcsErrFloorDenyReason3:   "Only one participant",
	CauseCodeGwMcsErrFloorDenyReason4:   "Retry-after timer has not expired",
	CauseCodeGwMcsErrFloorDenyReason5:   "Receive only",
	CauseCodeGwMcsErrFloorDenyReason6:   "No resources available",
	CauseCodeGwMcsErrFloorDenyReason7:   "Queue full",
	CauseCodeGwMcsErrFloorDenyReason255: "Other reason", // the floor control server does not grant the floor request due to the floor control server local policy

	CauseCodeGwGroupCryptoKeyNotFoundError: "Group crypto key not found error", // 加密组呼，未找到对应组秘钥
}

func NewErrCode(errCode int) int {
	if errCode != 0 {
		return errCode + CauseCodeGwMcsErrStart
	}
	return errCode
}
