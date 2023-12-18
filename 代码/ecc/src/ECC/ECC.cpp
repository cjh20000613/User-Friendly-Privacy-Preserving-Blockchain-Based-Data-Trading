#include <iostream>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <time.h>
#include <openssl/ec.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
using namespace std;

#define PUBKEY_PEM "pubkey.pem"
#define PRIVATE_PEM "private_pem"

static const char BASE16_ENC_TAB[] = "0123456789ABCDEF";
static const char BASE16_DEC_TAB[] =
{
	-1,									//0
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		//1-10
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		//11-20
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		//21-30
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,		//31-40
	-1,-1,-1,-1,-1,-1,-1, 0, 1, 2,		//41-50
	 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,		//51-60
	-1,-1,-1,-1,10,11,12,13,14,15,		//61-70 'A'~'F'
};

EVP_PKEY* EccKey() 
{
	//ec 密钥存放上下文
	auto key = EC_KEY_new();
	
	//选择椭圆曲线 设置生成密钥参数 国密sm2 支持 加解密
	// secp256k1 不支持加解密（比特币，以太坊用），支持签名和密钥交换
	auto group = EC_GROUP_new_by_curve_name(NID_sm2);
	if (!group)
	{
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	
	//设置密钥参数
	EC_KEY_set_group(key, group);

	//设置密钥参数
	EC_KEY_set_group(key, group);

	//生成密钥
	int re = EC_KEY_generate_key(key);
	if (re != 1)
	{
		EC_KEY_free(key);
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	//检查密钥
	re = EC_KEY_check_key(key);
	if (re != 1)
	{
		EC_KEY_free(key);
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	cout << "EC_KEY_check_key success!" << endl;

	EVP_PKEY* pkey = EVP_PKEY_new();
	EVP_PKEY_set1_EC_KEY(pkey, key);

	EC_KEY_free(key);

	//输出公钥pem文件
	FILE* pubf;
	errno_t err = fopen_s(&pubf, PUBKEY_PEM, "w");
	PEM_write_EC_PUBKEY(pubf, EVP_PKEY_get0_EC_KEY(pkey));

	FILE* prif;
	err = fopen_s(&prif, PRIVATE_PEM, "w");
	PEM_write_ECPrivateKey(prif, EVP_PKEY_get0_EC_KEY(pkey),
		NULL,
		NULL,
		0,
		NULL,
		NULL
	);
	fclose(pubf);
	fclose(prif);
	return NULL;
}

int EvpEccEncrypt(const unsigned char* in, int in_size, unsigned char* out)
{
	//1 读取pem中的公钥
	FILE* fp;
	errno_t err = fopen_s(&fp, PUBKEY_PEM, "r");
	if (!fp)
		return 0;
	EC_KEY* ec = NULL;
	PEM_read_EC_PUBKEY(fp, &ec, NULL, NULL);
	fclose(fp);

	if (!ec)
	{
		ERR_print_errors_fp(stderr);
		return 0;
	}

	//2 通过EVP_PKEY生成EVP_PKEY_CTX上下文
	EVP_PKEY* pkey = EVP_PKEY_new();
	EVP_PKEY_set1_EC_KEY(pkey, ec);
	auto ctx = EVP_PKEY_CTX_new(pkey, NULL);

	//3 加密初始化
	int re = EVP_PKEY_encrypt_init(ctx);
	if (re != 1)
	{
		ERR_print_errors_fp(stderr);
	}

	//ecc 加密
	size_t out_len = sizeof(out);
	EVP_PKEY_encrypt(ctx, out, &out_len, in, in_size);
	
	EVP_PKEY_free(pkey);
	EC_KEY_free(ec);
	EVP_PKEY_CTX_free(ctx);

	return out_len;
}

int EvpEccDecrypt(const unsigned char* in, int in_size, unsigned char* out)
{
	int out_size = 0;
	//1 打开pem文件获取私钥
	FILE* fp;
	errno_t err = fopen_s(&fp, PRIVATE_PEM, "r");
	if (!fp) return 0;
	EC_KEY* ec = NULL;
	PEM_read_ECPrivateKey(fp, &ec, NULL, NULL);
	fclose(fp);

	if (!ec)
	{
		ERR_print_errors_fp(stderr);
		return 0;
	}

	//2生成PKEY 并创建上下文
	EVP_PKEY* pkey = EVP_PKEY_new();
	EVP_PKEY_set1_EC_KEY(pkey, ec);
	auto ctx = EVP_PKEY_CTX_new(pkey, NULL);
	EVP_PKEY_free(pkey);
	EC_KEY_free(ec);

	//3解密初始化
	EVP_PKEY_decrypt_init(ctx);

	//4ecc 解密
	size_t out_len = sizeof(out);
	EVP_PKEY_decrypt(ctx, out, &out_len, in, in_size);
	cout << out_len << ":" << out << endl;

	return out_len;

}

int Base16Encode(const unsigned char* in, int size, char* out)
{
	for (int i = 0; i < size; i++)
	{
		//一个字节取出高四位和第四位 1000 0001 => 0000 1000
		char h = in[i] >> 4;  //移位丢弃低位 （0~15）
		char l = in[i] & 0x0F; // 0000 1111 去掉高位 (0~15)
		out[i * 2] = BASE16_ENC_TAB[h]; //(0~15) 映射到对应字符
		out[i * 2 + 1] = BASE16_ENC_TAB[l];
	}
	//base16 转码后空间扩大一倍 4位转成一个字符 1个字节转成两个字符
	return size * 2;
}

int Base16Decode(const string& in, unsigned char* out)
{
	//将两个字符拼成一个字节  B2E2CAD442617365313600
	for (int i = 0; i < in.size(); i += 2)
	{
		unsigned char ch = in[i];		//高位转换的字符   "B" =>66 :11
		unsigned char cl = in[i + 1];	//地位转换的字符   "2" =>50 :2
		unsigned char h = BASE16_DEC_TAB[ch];	//转换成原来的值
		unsigned char l = BASE16_DEC_TAB[cl];

		//两个4位拼成一个字节（8位）
		// 1000 <<4 =>		1000 0000
		// 0001     =>		0000 0001
		//            |     1000 0001  
		out[i / 2] = h << 4 | l;
	}
	return in.size() / 2;
}

int main(int argc, char* argv[])
{
	unsigned char data[1024] = "27";
	unsigned char out[2046] = { 0 };
	unsigned char out2[2046] = { 0 };


	int data_size = sizeof(data);

	//ecc 密钥对生成
	auto pkey = EccKey();

	//加密
	int len = EvpEccEncrypt(data, data_size, out);

	//int len = 1135;
	cout << len << endl;

	//注释 Ctrl+K Ctrl+C
	//曲线注释 Ctrl+K Ctrl+U

	int base16_len = sizeof(out);
	cout << base16_len << endl;
	char base16_out1[4096] = { 0 };
	unsigned char base16_out2[2046] = { 0 };
	int re = Base16Encode(out, base16_len, base16_out1);
	cout << re << ":" << base16_out1 << endl;
	re = Base16Decode(base16_out1, base16_out2);

	/*char base16_out3[4096] = "3082046B022100A813AD94DA995657B186EFD0A1DB68564AB84185B1A83EC815BB4F3C1DB0D3EE022016AE1766B996125DCF10DF942D36529D88A141ED593BA0DEB690AE0E340CCE080420732DB17BFBABB2AAC1A19A39F89D694D6CA68ACE3664188344F0DF9513A7684E04820400E2367DB2CB64C28D263A236BE175FE2A9936A52833388D59B24F62DBA79477EB44411C1ACBA2B6E121FD0A4F7C74FC09FF2897DF9E5124A05C0101F57BF4FC9DEBD8608F0DF57A37D78ABB227F7B3C2D78EFBD4404478B781FD4F6F25E58FC5C22077DBED5D7CED2F9B1320B837629614362EC93DBF0E5DC30EE6F9CE0706F028095F16680E263E3F8618B2BBE419AEA887E761DF9B208A6A7CE1663824999F9E33A0675230960AA1D29493A05FA3F7C0F888F7BD013398997B851D4C1FA4355FF97E23E8F31BA2B7E0171CADF7F99874188A0CB7538653218E24740EBD8553C69BB4A4E4FEC36C7A91395539BB1525059771E086AFD6B6735387B1F70336004ACE4E04FCCF5294A88B4CD4EC5CCC2CF11BAFA4BF36AF86D18C72AD50FA1FF15370964EC0BD41297F4C0B07F2220E042EE82676DACD0D93A35029BD808437EA07958DC2B1B44B6BFD627DA6BADD1BD14E8A845F7AA9A6BE8B8B9B1A24315C23FC66A0B567FC088934FA9A77AA662F63921049E560E01F4E684883C2C9E01945D1064037CB22EC82399E912C9A10B3AF6FABB9228FEE6C1FA4691223B2F0BF37EA68C8BCE890118A07DA26B24FEF245264784B60E48A1F4B3760937A047674BF3BB822A8F1D538C3DDF3B81D879F519B873B0E91F53F3641CE5CE7DA2EE59607B301554F406C7DCEA15BFC85E1DE44CF96A2C9A1FE51D6D8F77833079CEA7669819F3DEC8FFEF3ECB59B0AE0CA643C0C99C41E71F47CEEDD5BDE61CC372E6F99290326F7F2EE600DD55EDD84AC0F8EE9D45FB9864FE5DD27C6C57DFF45CDAFE202B72174E927FCB7C0E8D30FDAE7BAF871068CBCF37744DB75987151BC317A2B39A453E5E65CD9C3B68CAE961FF58CAEFF04301B891A29C7397B2E6D184CD1962E4C58F7E756D0E6A139521AEC06591B8804F48850A9F104894A7782D2D268F1F5DE236D4D7E183437FE40DF512B7B1981D8F4DEC46B958DF8331A18CB1A09609B5DE671E5E26A460154D57DBAA13D15D12A7DA00F7A744C71A097ADC7391E0D80F2117022E175E7504B620E0FC9413B8A89A47C148EF1D1D607604E48D94D4357009D26CC1ADF66EB131CAB8BB56ACB201D0F75BA1FBE7E29AD0A95AECE7FABD06A6D7D12538D7152186F271F962C472929D8278307A668973492203FC354C1DF32C38F2EAFDE003FD360CE4EF80D39C6BF342CE18A8022C20338208FBA9AB2C48208E7E0EE1A9EE61C62AF1E23933444811C524E1B557F16C3C292EB470FB04217432A947E15C96D9572E2D2CEB14FCD580B0B0DA95B548C923DB04327608E8CD46C5B1D1E9A2C7D761CB19191263FC22D31CA2339B041024690CA6F32602C213B1CA54DF007CA703453BC803E1CD41C5C2599647E5633020E01E299627902BCEC2D8D6448B1B8FDE4736D9C599CFD016CA3D1D853B2124E2567E2EADFE108C0";
	unsigned char base16_out4[2046] = { 0 };
	int aa = Base16Decode(base16_out3, base16_out4);*/

	
	//解密
	len = EvpEccDecrypt(base16_out2, len, out2);
	return 0;
}