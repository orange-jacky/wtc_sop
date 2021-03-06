#ifndef trans_type_h
#define trans_type_h

#define trans_type_max 60

char *trans_type[trans_type_max][2]={
	{"﻿VMX.ACCT.BLOCKCD.UPD", "帐户锁定码更新服务"},
	{"VMX.ACCT.DATA.INQ", "VMX.ACCT.DATA.INQ"},
	{"VMX.ACCT.DEMOGRAPHIC.INQ", "客户信息查询"},
	{"VMX.ACCT.DEMOGRAPHIC.UPD", "客户一般更新"},
	{"VMX.ACCT.DIRECT.DB.INQ", "直接转帐查询服务"},
	{"VMX.ACCT.DIRECT.DB.UPD", "直接转帐更新服务"},
	{"VMX.ACCT.INQ", "帐户查询服务"},
	{"VMX.ACCT.MEMO.DB.UPD", "客户MEMO DB更新"},
	{"VMX.ACCT.PLAN.PMT.HISTORY.INQ", "还款分配顺序的查询/计划还款历史查询"},
	{"VMX.ACCT.PMT.HISTORY.INQ", "还款历史查询服务"},
	{"VMX.ACCT.STMT.DATES.INQ", "对帐单日期查询服务"},
	{"VMX.ACCT.STMT.INQ", "对帐单查询服务"},
	{"VMX.ACCT.TO.CARD.NAV", "帐户至卡片导航服务"},
	{"VMX.ACCT.TRANSACTION.INQ", "交易查询服务"},
	{"VMX.ACCT.TRANSACTION.INQ", "交易查询服务"},
	{"VMX.CARD.ACTIVATION.UPD", "卡片激活服务"},
	{"VMX.CARD.BLOCKCD.UPD", "卡片锁定码更新服务"},
	{"VMX.CARD.DATA.INQ", "卡片信息查询"},
	{"VMX.CARD.DATA.UPD", "卡片一般更新服务"},
	{"VMX.CARD.NEWISSUE.RQST", "请求发行新卡服务"},
	{"VMX.CARD.PIN.REISSUE.RQST", "请求密码重发服务"},
	{"VMX.CMS.REL.ACCTREC.INQ", "VMX.CMS.REL.ACCTREC.INQ"},
	{"VMX.CUST.TO.ACCT.NAV", "客户至帐户导航服务"},
	{"VMX.CUSTOMER.LOCATE.INQ", "就客户姓名或ID定位的姓名和地址"},
	{"VMX.PID.TO.CUST.NAV", "通过证件号查询客户信息"},
	{"VMX.ACCT.INQ", "帐户查询服务"},
	{"VMX.ACCT.AUTHLIM.UPD", "账户层授权额度覆盖标志的修改"},
	{"VMX.ACCT.CRLIMIT.UPD", "客户层额度修改"},
	{"VMX.ACTIVE.HISTORY.INQ", "CTA催收记录的查询"},
	{"VMX.CARD.INSTFLG.UPD", "自动分期标志的修改"},
	{"VMX.CUST.STMTMAIL.UPD", "账单产生标志修改"},
	{"VMX.EMBOSSER.MON.TXNLMT.UPD", "卡片层交易金额/笔数限制修改"},
	{"VMX.ACCT.PCTID.UPD", "更新帐户的居住地信息"},
	{"VMX.ACCT.CARD.DETAIL.INQ", "查询卡片列表及详细信息"},
	{"VMX.CUST.ACCT.DETAIL.INQ", "查询帐户列表及详细信息"},
	{"VMX.CARD.DATA.UPD", "卡片一般更新服务"},
	{"VMX.ACCT.BILLING.HIST.INQ", "查询帐单结单记录"},
	{"VMX.ACCT.BILLING.ALLOC.INQ", "帐单结单分配查询"},
	{"VMX.ACCT.PMT.ALLOC.INQ", "还款分配查询"},
	{"VMX.CARD.BLOCKCD.BATCH.UPD", "批量更新卡片锁定码"},
	{"VMX.ACCT.BILLCYC.BATCH.UPD", "批量更新帐单周期"},
	{"VMX.ACCT.DEMOGRAPHIC.UPD", "客户一般更新"},
	{"VMX.ACCT.STMT.STATISTIC.INQ", "当期帐单信息查询"},
	{"VMX.ACCT.CONTACT.HIST.INQ", "ASM帐户操作信息查询"},
	{"VMX.CARD.ACTIVITY.INQ", "FAS卡号信息查询"},
	{"VMX.ACCT.BALANCE.INQ", "用卡信息查询"},
	{"VMX.CARD.REPLACE.RQST", "补卡优化交易"},
	{"VMX.ACCT.LIST.INQ", "查询帐号卡号列表"},
	{"VMX.CARD.CANCEL.AUTH.RQST", "人工授权取消交易"},
	{"VMX.ACCT.MEMO.DB.UPD", "客户memo DB一般更新"},
	{"VMX.PHONE.TO.CARD.NAV", "手机号查询卡号"},
	{"VMX.ACCT.GENERIC.UPD", "账户信息更新服务"},
	{"VMX.CUST.ACCT.CARD.INQ", "通过客户号查询账户层和卡片层信息"},
	{"VMX.CUST.ACCT.CARD.INQ", "查询是否能申请预制卡"},
	{"VMX.CUST.ADD", "创建客户记录"},
	{"VMX.PID.TO.CUST.NAV", "通过证件号查询客户信息"},
	{"VMX.CUSTLINKACCT.UPD", "客户信息和预制卡账户、卡片的关联关系建立"},
	{"VMX.ECIFID.TO.CUST.NAV", "通过ECIF ID查询客户信息"},
	{"VMX.CARD.2IN1REPL.RQST ", "存贷合一卡柜台渠道新增补换卡"},
	{"NULL","NULL"}
};

#endif
