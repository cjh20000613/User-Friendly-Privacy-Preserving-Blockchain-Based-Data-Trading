#pragma once
#include <string>
#include <openssl/des.h>
enum XSecType
{
	XDES_ECB,
	XDES_CBC,
	X3DES_ECB,
	X3DES_CBC,
	XAES128_ECB,
	XAES128_CBC,
	XAES192_ECB,
	XAES192_CBC,
	XAES256_ECB,
	XAES256_CBC,
	XSM4_ECB,
	XSM4_CBC
};
/*
XSec sec;
sec.Init(SDES_ECB,"12345678",true)
*/
class XSec
{
public:
	///////////////////////////////////////////////////////////////////////
	/// 初始化加密对象，清理之前的数据
	/// @para type 加密类型
	/// @para pass 密钥，可以是二进制
	/// @is_en true加密  false解密
	/// @return 是否成功
	virtual bool Init(XSecType type, const std::string& pass, bool is_en);

	/////////////////////////////////////////////////////////////////
	/// 加解密数据
	/// @para in 输入数据
	/// @para in_size 输入数据大小
	/// @para out 输出数据
	/// @return 成功返回加解密后数据字节大小，失败返回0
	virtual int Encrypt(const unsigned char* in, int in_size, unsigned char* out, bool is_end = true);

	virtual void close();

private:
	//////////////////////////////////////////////////////////////////
	/// DES ECB模式加密
	int EnDesECB(const unsigned char* in, int in_size, unsigned char* out, bool is_end);

	////////////////////////////////////////////////////////////////////////
	/// DES ECB模式解密
	int DeDesECB(const unsigned char* in, int in_size, unsigned char* out, bool is_end);

	//////////////////////////////////////////////////////////////////
	/// DES CBC模式加密
	int EnDesCBC(const unsigned char* in, int in_size, unsigned char* out, bool is_end);

	////////////////////////////////////////////////////////////////////////
	/// DES CBC模式解密
	int DeDesCBC(const unsigned char* in, int in_size, unsigned char* out, bool is_end);

	//DES算法密钥
	DES_key_schedule ks_;

	//加密算法类型
	XSecType type_;

	//加密 解密
	bool is_en_;

	//数据块大小 分组大小
	int block_size_ = 0;

	//初始化向量
	unsigned char iv_[128] = { 0 };

	//加解密上下文
	void* ctx_ = 0;
};

