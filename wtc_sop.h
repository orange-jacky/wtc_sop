#ifndef wtc_sop_h
#define wtc_sop_h

#define wtc_sop_type_max	116

char *wtc_sop_type[wtc_sop_type_max][2]={
	{"5506", "协议支付签约/修改限额"},
	{"5510", "商户开通/关闭"},
	{"5514", "银行卡直接支付客户签约维护"},
	{"ZF03", "普通支付验签"},
	{"ZF04", "商户签约申请"},
	{"ZF05", "商户签约"},
	{"ZF07", "商户基本信息修改"},
	{"ZF08", "商户签约修改"},
	{"ZF10", "商户证书上传"},
	{"ZF19", "银商宝开通/关闭"},
	{"ZF30", "银商宝内部户的参数添加、修改"},
	{"ZF33", "商户联系信息维护"},
	{"ZF34", "银商宝失效订单删除"},
	{"ZF39", "临时商户信息的删除"},
	{"ZF40", "分期支付客户手续费计算"},
	{"ZF43", "分期商户费率维护"},
	{"ZF46", "客户账号合法性和签约信息验证"},
	{"ZF47", "客户异常签约记录删除"},
	{"ZF55", "免签约默认限额设置"},
	{"ZF57", "商户交易控制维护"},
	{"ZF59", "机构交易控制添加、修改"},
	{"ZF61", "利润分配控制添加、修改"},
	{"ZF62", "业务参数设置、修改"},
	{"ZF65", "机构内部帐号修改"},
	{"ZF67", "商户类型增加/修改"},
	{"ZF68", "联机服务器参数重置"},
	{"ZF69", "验证密码并查询客户信息"},
	{"ZF78", "商户支付白名单维护"},
	{"ZF79", "手动对账通知"},
	{"ZF83", "批量退货"},
	{"ZF86", "实时交易查询"},
	{"ZF87", "协议支付协议添加，修改"},
	{"ZF91", "商户系统参数维护"},
	{"ZF93", "商户渠道限额维护"},
	{"ZF97", "协议支付验签"},
	{"ZF01", "普通支付"},
	{"ZF02", "退货"},
	{"ZF20", "预付款"},
	{"ZF38", "手机支付"},
	{"ZF41", "分期支付"},
	{"ZF71", "储值卡支付"},
	{"ZF72", "储值卡退货"},
	{"ZF81", "协议支付"},
	{"ZF82", "提现"},
	{"ZF95", "协议退货"},
	{"5568", "B2B银商宝支付退汇"},
	{"ZF21", "付款"},
	{"ZF23", "退款"},
	{"ZF22", "付款确认"},
	{"ZF24", "退款确认"},
	{"ZF36", "支付交易信息登记"},
	{"5507", "协议支付签约信息查询"},
	{"5508", "商户列表信息查询"},
	{"5509", "商户渠道限额查询"},
	{"5512", "商户签约信息查询"},
	{"5513", "商户签约交易流水查询"},
	{"5515", "银行卡直接支付客户签约查询"},
	{"5517", "对公客户及证书版客户查询"},
	{"5518", "交易信息查询"},
	{"5567", "B2B银商宝跨行付款查询"},
	{"ZF06", "客户签约信息查询"},
	{"ZF09", "商户账务信息查询"},
	{"ZF12", "商户交易信息查询"},
	{"ZF14", "商户签约信息查询"},
	{"ZF15", "商户单笔交易查询"},
	{"ZF16", "协议支付客户签约信息查询"},
	{"ZF17", "银行卡余额查询"},
	{"ZF25", "银商宝订单信息查询"},
	{"ZF26", "银商宝单笔订单查询"},
	{"ZF27", "银商宝签约信息查询"},
	{"ZF28", "银商宝合同信息查询"},
	{"ZF29", "跨行手续费欠款清单查询"},
	{"ZF31", "银商宝内部户的参数查询"},
	{"ZF32", "商户联系信息查询"},
	{"ZF35", "账户签约状态查询"},
	{"ZF37", "支付交易信息查询"},
	{"ZF42", "分期商户费率查询"},
	{"ZF48", "上行短信退订网上支付客户签约信息查询"},
	{"ZF54", "免签约默认限额查询"},
	{"ZF56", "商户交易控制查询"},
	{"ZF58", "机构交易控制信息查询"},
	{"ZF60", "利润分配控制信息查询"},
	{"ZF63", "业务参数查询"},
	{"ZF64", "机构内部帐号查询"},
	{"ZF66", "商户类型查询"},
	{"ZF73", "储值卡交易明细查询"},
	{"ZF74", "储值卡订单查询"},
	{"ZF75", "储值卡账务明细查询"},
	{"ZF76", "储值卡余额查询"},
	{"ZF77", "商户支付白名单查询"},
	{"ZF84", "支付限额查询"},
	{"ZF89", "协议支付协议查询"},
	{"ZF90", "单笔实时交易查询"},
	{"ZF92", "商户系统参数查询"},
	{"ZF94", "商户渠道限额列表查询"},
	{"ZF96", "协议同步"},
	{"ZF98", "商户批量退货明细查询"},
	{"ZF99", "商户批量退货批次查询"},
	{"EP00", "更新第三方对账文件下载地址"},
	{"EP01", "跨行支付确认交易（后台）"},
	{"EP02", "跨行退货交易"},
	{"EP03", "跨行支付下单交易"},
	{"EP04", "跨行支付确认交易（前台）"},
	{"EP05", "新模式跨行支付下单"},
	{"EP06", "支付宝批量代发完成通知"},
	{"EP07", "支付宝批量代发手动上传"},
	{"EP08", "支付宝充值成功通知"},
	{"EP10", "已关闭商户的恢复"},
	{"EP11", "本行交易明细查询交易"},
	{"EP12", "跨行交易明细查询交易"},
	{"ZF49", "快捷支付"},
	{"EP91", "第三方参数查询交易"},
	{"EP92", "第三方参数维护交易"},
	{"EP95", "单笔退货"},
	{"EP97", "支付宝通讯验签"},
	{"NULL","NULL"}
};



#endif