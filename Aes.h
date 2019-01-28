// AES cryptoalgorithm implementation
// Coded by Sheroz Khaydarov
// 12.07.2005

#include "string.h"

class CAesCrypt
{
private:
	unsigned char nSbox[16][16];
	unsigned char niSbox[16][16];
	unsigned char nRcon[11][4];
	unsigned char nKeyW[60][4]; // maximum for 4*(14+1)
	unsigned char nState[4][4];
	unsigned char nTmpState[4][4]; // for MixColumn and InvMixColum methods

	// for fast and secure GF multiplication
	unsigned char nMultPow[512];
	unsigned char nMultLog[256];

	int m_nCycleCount;
	int m_nKeySize; // Key size in 32 bit words

	int m_nRound;

	bool m_bDump;
	std::string strDump;

private:

	void AddRoundKey();
	void SubBytes();
	void ShiftRows();
	void MixColumns();
	void InvSubBytes();
	void InvShiftRows();
	void InvMixColumns();

	void DumpHex(const char *szTitle, void * pByte, int nLen);
	void DumpStateHex(const char *szTitle);
	unsigned char GF_Mul(unsigned char a, unsigned char b);
	unsigned char GF_HiBit(unsigned char x);

public:

	CAesCrypt();

	bool SetKey(void * pKey, int nKeyLen);
	void Crypt(void * pData, void * pCipher);
	void Decrypt(void * pCipher, void * pData);

	void EnableDump(bool bDump=true) { m_bDump=bDump; };
	const char * GetDump() { return strDump.c_str(); };
};
