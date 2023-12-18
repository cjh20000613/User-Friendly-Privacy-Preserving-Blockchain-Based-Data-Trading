#include "XSec.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
using namespace std;

void XSec::close()
{
	//初始化iv_
	memset(iv_, 0, sizeof(iv_));
	if (ctx_)
	{
		EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)ctx_);
		ctx_ = nullptr;
	}
}


///////////////////////////////////////////////////////////////////////
/// 初始化加密对象，清理之前的数据
/// @para type 加密类型
/// @para pass 密钥，可以是二进制
/// @is_en true加密  false解密
/// @return 是否成功
bool XSec::Init(XSecType type, const std::string& pass, bool is_en)
{
	close();
	this->type_ = type;
	this->is_en_ = is_en;
	

	//密钥补全或丢弃
	unsigned char key[32] = {0}; //少的补充0
	int key_size = pass.size();

	//加解密算法
	const EVP_CIPHER* cipher = 0;

	switch(type)
	{
	case XDES_ECB:
	case XDES_CBC:
		block_size_ = DES_KEY_SZ;
		//超出8字节的丢弃
		if (key_size > block_size_)
		{
			key_size = block_size_;
		}
		///密码策略 ：超出8字节的丢弃，少的补充0
		memcpy(key, pass.data(), key_size);
		DES_set_key((const_DES_cblock*)key, &ks_);
		return true;

	case X3DES_ECB:
		cipher = EVP_des_ede3_ecb();
		break;
	case X3DES_CBC:
		cipher = EVP_des_ede3_cbc();
		break;
	case XAES128_ECB:
		cipher = EVP_aes_128_ecb();
		break;
	case XAES128_CBC:
		cipher = EVP_aes_128_cbc();
		break;
	case XAES192_ECB:
		cipher = EVP_aes_192_ecb();
		break;
	case XAES192_CBC:
		cipher = EVP_aes_192_cbc();
		break;
	case XAES256_ECB:
		cipher = EVP_aes_256_ecb();
		break;
	case XAES256_CBC:
		cipher = EVP_aes_256_cbc();
		break;
	case XSM4_ECB:
		cipher = EVP_sm4_ecb();
		break;
	case XSM4_CBC:
		cipher = EVP_sm4_cbc();
		break;
	default:
		break;
	}

	if (!cipher) return false;

	//分组大小
	block_size_ = EVP_CIPHER_block_size(cipher);

	if (key_size > EVP_CIPHER_key_length(cipher))
		key_size = EVP_CIPHER_key_length(cipher);
	memcpy(key, pass.data(), key_size);

	//加解密上下文
	ctx_ = EVP_CIPHER_CTX_new();

	//初始化上下文
	int re = EVP_CipherInit(
		(EVP_CIPHER_CTX*)ctx_,
		cipher, key, iv_, is_en_
	);
	if(!re)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}

	//cout << "EVP_CipherInit success!" << endl;

	return true;


}

/////////////////////////////////////////////////////////////////
/// 加解密数据
/// @para in 输入数据
/// @para in_size 输入数据大小
/// @para out 输出数据
/// @return 成功返回加解密后数据字节大小，失败返回0
int XSec::Encrypt(const unsigned char* in, int in_size, unsigned char* out, bool is_end)
{
	if (type_ == XDES_ECB) 
	{
		if (is_en_) 
		{
			return EnDesECB(in, in_size, out, is_end);
		}
		else
		{
			return DeDesECB(in, in_size, out, is_end);
		}
	}
	else if(type_ == XDES_CBC)
	{
		if (is_en_)
		{
			return EnDesCBC(in, in_size, out, is_end);
		}
		else
		{
			return DeDesCBC(in, in_size, out, is_end);
		}
	}

	//不是最后一块数据，不填充PKCS7
	if (is_end)
	{
		EVP_CIPHER_CTX_set_padding((EVP_CIPHER_CTX*)ctx_, EVP_PADDING_PKCS7);
	}
	else
	{
		EVP_CIPHER_CTX_set_padding((EVP_CIPHER_CTX*)ctx_, 0);
	}

	int out_len = 0;
	EVP_CipherUpdate((EVP_CIPHER_CTX*)ctx_, out, &out_len, in, in_size);
	if (out_len <= 0) return 0;
	
	//取出填充的数据
	int out_padding_len = 0;
	EVP_CipherFinal((EVP_CIPHER_CTX*)ctx_, out + out_len, &out_padding_len);

	return out_len + out_padding_len;
}


//////////////////////////////////////////////////////////////////
/// DES ECB模式加密
int XSec::EnDesECB(const unsigned char* in, int in_size, unsigned char* out, bool is_end)
{
	///数据填充 PKCS7 Padding
	/*
	假设数据长度需要填充n（n>0）个字节才对齐，那么填充n个字节，每个字节都是n；
	如果数据本身就已经对齐了，则填充一块长度为块大小的数据，每个字节都是块大小
	*/
	unsigned char pad[8] = { 0 };
	int padding_size = block_size_ - (in_size % block_size_);
	//填入补充的字节大小
	memset(pad, padding_size, sizeof(pad));

	int i = 0;
	for (; i < in_size; i += block_size_)
	{
		//最后一块数据，小于block_size_ 需要填充
		if (in_size - i < block_size_)
		{
			//填入数据
			memcpy(pad, in + i, in_size - i);
			break;
		}
		DES_ecb_encrypt(
			(const_DES_cblock*)(in + i),
			(DES_cblock*)(out + i),
			&ks_,
			DES_ENCRYPT
		);
	}

	if (!is_end) return in_size;

	//补充 PKCS7结尾
	DES_ecb_encrypt((const_DES_cblock*)pad, (DES_cblock*)(out + i), &ks_, DES_ENCRYPT);
	return in_size + padding_size;
}

////////////////////////////////////////////////////////////////////////
/// DES ECB模式解密
int XSec::DeDesECB(const unsigned char* in, int in_size, unsigned char* out, bool is_end)
{
	for (int i = 0; i < in_size; i += block_size_)
	{
		DES_ecb_encrypt(
			(const_DES_cblock*)(in + i),
			(DES_cblock*)(out + i),
			&ks_,
			DES_DECRYPT
		);
	}
	if (is_end)
		//PKCS7 最后一个字节存储的补充字节数
		return in_size - out[in_size - 1];
	else
		return in_size;
}


//////////////////////////////////////////////////////////////////
/// DES CBC模式加密
int XSec::EnDesCBC(const unsigned char* in, int in_size, unsigned char* out, bool is_end)
{
	//填充的数据 PKCS7 Padding
	unsigned char pad[8] = { 0 };
	int padding_size = block_size_ - (in_size % block_size_);
	//填入补充的字节大小
	memset(pad, padding_size, sizeof(pad));
	//block 整数倍大小
	int size1 = in_size - (in_size % block_size_);
	//ncbc保留iv修改
	DES_ncbc_encrypt(in, out,
		size1,
		&ks_,
		(DES_cblock*)iv_,
		DES_ENCRYPT
	);

	if (!is_end) return in_size;

	//PACS7 Padding
	if (in_size % block_size_ != 0) 
	{
		//复制剩余数据
		memcpy(pad, in + size1, (in_size % block_size_));
	}
	DES_ncbc_encrypt(pad, out + size1,
		sizeof(pad),
		&ks_,
		(DES_cblock*)iv_,
		DES_ENCRYPT
	);
	return in_size + padding_size;
}

////////////////////////////////////////////////////////////////////////
/// DES CBC模式解密
int XSec::DeDesCBC(const unsigned char* in, int in_size, unsigned char* out, bool is_end)
{
	DES_ncbc_encrypt(in, out, in_size, &ks_, (DES_cblock*)iv_, DES_DECRYPT);
	if (is_end)
		return in_size - out[in_size - 1];
	else
		return in_size;
}