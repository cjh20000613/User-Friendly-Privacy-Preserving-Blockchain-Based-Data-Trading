#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <fstream>
#include "XSec.h"
#include <ctime>

using namespace std;

bool EncryptFile(string passwd, string in_filename, string out_filename,bool is_enc)
{
	//选择加解密算法，可以替换
	auto cipher = EVP_des_ede3_cbc();
	
	//输入文件大小
	int in_file_size = 0;

	//输出文件大小
	int out_file_size = 0;
	ifstream ifs(in_filename, ios::binary);
	if (!ifs) return false;
	ofstream ofs(out_filename, ios::binary);
	if (!ofs)
	{
		ifs.close();
		return false;
	}
	//加解密上下文
	auto ctx = EVP_CIPHER_CTX_new();
	//密钥初始化
	unsigned char key[128] = { 0 };
	int key_size = EVP_CIPHER_key_length(cipher);//获取密钥长度
	if (key_size > passwd.size()) //密码少了
	{
		key_size = passwd.size();
	}
	memcpy(key, passwd.data(), key_size);

	unsigned char iv[128] = { 0 }; //初始化向量

	int re = EVP_CipherInit(ctx, cipher, key, iv, is_enc);
	if (!re)
	{
		ERR_print_errors_fp(stderr);
		ifs.close();
		ofs.close();
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	
	unsigned char buf[1024] = { 0 };
	unsigned char out[1024] = { 0 };
	int out_len = 0;
	//读文件 => 加解密文件 => 写入文件
	while (!ifs.eof())
	{
		//1读文件
		ifs.read((char*)buf, sizeof(buf));
		int count = ifs.gcount();
		if (count <= 0) break;
		in_file_size += count;//统计读取文件大小

		//2加解密文件
		EVP_CipherUpdate(ctx, out, &out_len, buf, count);
		if (out_len <= 0) break;

		//3写文件
		ofs.write((char*)out, out_len);
		out_file_size += out_len;
	}

	//取出最后一块数据
	EVP_CipherFinal(ctx, out, &out_len);
	if (out_len > 0)
	{
		ofs.write((char*)out, out_len);
		out_file_size += out_len;
	}

	ifs.close();
	ofs.close();
	EVP_CIPHER_CTX_free(ctx);
	cout << "in_file_size:" << in_file_size << endl;
	cout << "out_file_size:" << out_file_size << endl;
	return true;
}

bool XSecEncryptFile(string passwd, string in_filename, string out_filename, bool is_enc)
{
	ifstream ifs(in_filename, ios::binary);
	if (!ifs) return false;
	ofstream ofs(out_filename, ios::binary);
	if (!ofs)
	{
		ifs.close();
		return false;
	}
	XSec sec;
	sec.Init(XAES128_CBC, passwd, is_enc);

	unsigned char buf[1024] = { 0 };
	unsigned char out[1024] = { 0 };
	int out_len = 0;
	//读文件 => 加解密文件 => 写入文件
	while (!ifs.eof())
	{
		//1读文件
		ifs.read((char*)buf, sizeof(buf));
		int count = ifs.gcount();
		if (count <= 0) break;
		bool is_end = false;
		if (ifs.eof())
			is_end = true;
		out_len = sec.Encrypt(buf, count, out, is_end);
		if (out_len <= 0)
			break;
		ofs.write((char*)out, out_len);
	}
	
	sec.close();
	ifs.close();
	ofs.close();
	return true;
}

//测试算法性能
class TestCipher
{
public:
	void Close()
	{
		delete in_;
		in_ = nullptr;
		delete de_;
		de_ = nullptr;
		delete en_;
		en_ = nullptr;
	}

	void Init(int data_size)
	{
		Close();
		data_size_ = data_size;
		in_ = new unsigned char[data_size];
		en_ = new unsigned char[data_size + 128];
		de_ = new unsigned char[data_size + 128];

		//测试数据赋初值
		unsigned int data = 1;
		for (int i = 0; i < data_size; i += sizeof(data))
		{
			memcpy(in_ + i, &data, sizeof(data));
			data++;
		}
		memset(en_, 0, data_size + 128);
		memset(de_, 0, data_size + 128);
	}
	void Test(XSecType type, string type_name)
	{
		memset(en_, 0, data_size_ + 128);
		memset(de_, 0, data_size_ + 128);
		cout << "================" << type_name << endl;
		XSec sec;

		//加密
		sec.Init(type, passwd, true);
		auto start = clock();
		int en_size = sec.Encrypt(in_, data_size_, en_);
		auto end = clock();
		cout <<en_size << "加密花费时间:" << (double)((end - start) / (double)CLOCKS_PER_SEC) << "秒" << endl;

		//解密
		sec.Init(type, passwd, false);
		start = clock();
		int de_size = sec.Encrypt(en_, en_size, de_);
		end = clock();
		cout << en_size << "解密花费时间:" << (double)((end - start) / (double)CLOCKS_PER_SEC) << "秒" << endl;

	}

	~TestCipher()
	{
		Close();
	}
private:

	//测试数据字节数
	int data_size_ = 0;

	//测试数据
	unsigned char* in_ = nullptr;
	
	//加密后数据
	unsigned char* en_ = nullptr;
	
	//解密后数据
	unsigned char* de_ = nullptr;

	//密码 适应各种强度
	string passwd = "12345678ABCDEFGHabcdefgh!@#$%^&*";
};

//ci.Test(XDES_ECB, "XDES_ECB");
#define TEST_CIPHER(s) ci.Test(s, #s);

int main(int argc, char* argv[]) 
{
	TestCipher ci;
	ci.Init(1024 * 1024 * 100);//10MB
	/*
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
	*/

	/*TEST_CIPHER(XDES_ECB);
	TEST_CIPHER(XDES_CBC);
	TEST_CIPHER(X3DES_ECB);
	TEST_CIPHER(X3DES_CBC);
	TEST_CIPHER(XAES128_ECB);
	TEST_CIPHER(XAES128_CBC);
	TEST_CIPHER(XAES192_ECB);
	TEST_CIPHER(XAES192_CBC);
	TEST_CIPHER(XAES256_ECB);
	TEST_CIPHER(XAES256_CBC);
	TEST_CIPHER(XSM4_ECB);
	TEST_CIPHER(XSM4_CBC);*/

	//getchar();


	//加密文件
	XSecEncryptFile("1234567812345678", "DATA.txt", "data.encrypt.txt", true);
	//解密文件
	XSecEncryptFile("1234567812345678", "data.encrypt.txt", "data.decrypt.txt", false);
	getchar();

	const unsigned char data[] = "12345678123456781";	//输入
	int data_size = strlen((char*)data);				//输入数据大小
	cout << "data_size:" << data_size << endl;
	unsigned char out[1024] = { 0 };					//输出
	unsigned char key[128] = "12345678901234567890";	//密钥
	unsigned char iv[128] = { 0 };						//初始化向量
	int out_size = 0;

	//三重DES 3DES算法
	auto cipher = EVP_des_ede3_cbc();

	//获取算法的分组大小
	int block_size = EVP_CIPHER_block_size(cipher);
	int key_size = EVP_CIPHER_key_length(cipher);
	int iv_size = EVP_CIPHER_iv_length(cipher);
	cout << "block_size = " << block_size << endl;
	cout << "key_size = " << key_size << endl;
	cout << "iv_size = " << iv_size << endl;
	
	//加解密上下文
	auto ctx = EVP_CIPHER_CTX_new();

	//加密算法初始化
	int re = EVP_CipherInit(ctx, cipher, key, iv, 1);	// 1表示加密

	if (!re)
	{
		ERR_print_errors_fp(stderr);
		getchar();
		return -1;
	}
	cout << "EVP_CipherInit success!" << endl;

	//默认 PKCS7 补充大小 EVP_PADDING_PKCS7
	//关闭自动填充
	//EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

	//只处理分组大小的数据
	//如果取消自动填充，多余数据丢弃
	//如果自动填充，则在EVP_CipherFinal中获取数据
	EVP_CipherUpdate
	(
		ctx,
		out,				//输出
		&out_size,			//输出数据大小
		data,				//输入数据
		data_size
	);
	cout << "EVP_CipherUpdate size:" << out_size << endl;
	//取出最后一块数据（需要填充的），或者是padding补充的数据
	int padding_size = 0;
	EVP_CipherFinal(ctx, out + out_size, &padding_size);
	cout << "padding_size = " << padding_size << endl;
	out_size += padding_size;
	cout << out_size << ":" << out << endl;


	/////////////////////////////////////////////////////////////////
	///解密数据 使用原来的ctx
	re = EVP_CipherInit(ctx,cipher,key,iv,0);	// 0表示解密
	if (!re)
	{
		ERR_print_errors_fp(stderr);
	}

	//解密密文后存放的明文
	unsigned char out2[1024] = { 0 };
	int out2_size = 0;
	//解密数据	填充数据取不到
	EVP_CipherUpdate(ctx, out2, &out2_size, out, out_size);
	cout << "EVP_CipherUpdate out2_size = " << out2_size << endl;

	//取出填充数据
	EVP_CipherFinal(ctx, out2 + out2_size, &padding_size);
	cout << "EVP_CipherUpdate Padding_size = " << padding_size << endl;
	out2_size += padding_size;
	cout << out2_size << ":" << out2 << "|" << endl;

	//释放上下文
	EVP_CIPHER_CTX_free(ctx);
	getchar();
	return 0;
}