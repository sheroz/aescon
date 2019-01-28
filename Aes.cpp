// AES cryptoalgorithm implementation
// Coded by Sheroz Khaydarov
// 12.07.2005

// Used litreature:
// 1. James McCaffrey, MSDN Magazine 2003 #11
// Original AES codes
// 2. Optimised ANSI C code for the Rijndael cipher (now AES) 
// @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
// @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
// @author Paulo Barreto <paulo.barreto@terra.com.br> 
#include "stdafx.h"
#include "aes.h"

unsigned char CAesCrypt::GF_HiBit(unsigned char x)
{
	x  = ((x >> 1) | (x >> 2));
	x |= (x >> 2);
	x |= (x >> 4);
	x  = (x + 1) >> 1;
	return x;
};

unsigned char CAesCrypt::GF_Mul(unsigned char a, unsigned char b)
{

	//  this takes no memory, but slower and the computing times are not equal ...
	/*
	#define GF_WPOLY     0x011b
	#define gf_mb02(x)   ((x<<1) ^ (((x>>7) & 1) * GF_WPOLY))
	#define gf_mb04(x)   ((x<<2) ^ (((x>>6) & 1) * GF_WPOLY) ^ (((x>>6) & 2) * GF_WPOLY))
	#define gf_mb08(x)   ((x<<3) ^ (((x>>5) & 1) * GF_WPOLY) ^ (((x>>5) & 2) * GF_WPOLY) ^ (((x>>5) & 4) * GF_WPOLY))
	#define gf_mb03(x)   (gf_mb02(x) ^ x)
	#define gf_mb09(x)   (gf_mb08(x) ^ x)
	#define gf_mb0b(x)   (gf_mb08(x) ^ gf_mb02(x) ^ x)
	#define gf_mb0d(x)   (gf_mb08(x) ^ gf_mb04(x) ^ x)
	#define gf_mb0e(x)   (gf_mb08(x) ^ gf_mb04(x) ^ gf_mb02(x)) 
	*/

	//  this takes 256+256=512 bytes memory, but % takes time ...
	//	return (a && b) ? nMultPow[(nMultLog[a] + nMultLog[b])%255] : 0; 
	
	//  this takes 512+256=768 bytes memory, but faster ...
	return (a && b) ? nMultPow[nMultLog[a] + nMultLog[b]] : 0;
} 

void CAesCrypt::DumpHex(const char *szTitle, void * pByte, int nLen)
{
	strDump+=szTitle;
	char sChar[4];
	for(int i=0;i<nLen;i++)
	{
		sprintf(sChar,"%02x ",((unsigned char *)pByte)[i]);
		strDump+=sChar;
	}
	strDump+="\n";
}
void CAesCrypt::DumpStateHex(const char *szTitle)
{
	strDump+=szTitle;
	char sChar[4];
	for(int i=0;i<4;i++)
		for(int j=0;j<4;j++)
		{
			sprintf(sChar,"%02x ",nState[j][i]);
			strDump+=sChar;
		}
	strDump+="\n";
}

CAesCrypt::CAesCrypt()
{
	m_nCycleCount=0;
	m_nKeySize=0;
	strDump="";
	bool bDump=false;
	int nGF_BPOLY=0x1b;

	// nSbox таблицани тузамиз
	unsigned int i,w,x;
	for(x = 0; x < 256; x++)
	{
		// the inverse of the finite field element 
		unsigned char p1 = x, p2 = nGF_BPOLY, n1 = GF_HiBit(x), n2 = 0x80, v1 = 1, v2 = 0;
	    w=x;
	    for(;x >= 2;)
	    {
			if(!n1)
			{
				w=v1;
				break;
			}
			while(n2 >= n1)
			{   
	            n2 /= n1; p2 ^= p1 * n2; v2 ^= v1 * n2; n2 = GF_HiBit(p2);
		    }
			if(!n2)
			{
				w=v2;
				break;
			}
			while(n1 >= n2)
			{   
				n1 /= n2; p1 ^= p2 * n1; v1 ^= v2 * n1; n1 = GF_HiBit(p1);
			}
		}

		w ^= (w<<1)^(w<<2)^(w<<3)^(w<<4);
        ((unsigned char *)nSbox)[x] = 0x63^(unsigned char)(w^(w>>8));
	}

	// niSbox таблицани тузамиз
	for(i = 0; i < 256; i++)
	{
		int x,y;
		x=i>>4;
		y=i&0x0f;
		unsigned char n1=nSbox[x][y];
		x=n1>>4;
		y=n1&0x0f;
		niSbox[x][y]=i;
	}

	// GF(2^8) майдонида тез купайтириш таблицаларини тузамиз
    // nGF_WPOLY as modular polynomial - the simplest primitive
    // root is 0x03, used here to generate the tables

    i = 0; w = 1; 
	int nGF_WPOLY=0x011b;
    do
    {   
        nMultPow[i] = (unsigned char)w;
        nMultPow[i+255] =nMultPow[i];
        nMultLog[w] = (unsigned char)i++;
        w ^=  (w << 1) ^ (w & 0x80 ? nGF_WPOLY : 0);
    } while (w != 1);

	// nRcon таблицани тулдирамиз
	for (int i=0;i<11;i++)
		for(int j=0;j<4;j++)
			nRcon[i][j]=0;

	nRcon[1][0]=1;
	for (int r=2;r<11;r++)
		nRcon[r][0]=GF_Mul(nRcon[r-1][0],0x02);
}

void CAesCrypt::SubBytes()
{
	unsigned char * pVal = (unsigned char *) nState;
	for (int i=0;i<16;i++)
		pVal[i]=nSbox[pVal[i]>>4][pVal[i]&0x0f];
}
void CAesCrypt::InvSubBytes()
{
	unsigned char * pVal = (unsigned char *) nState;
	for (int i=0;i<16;i++)
		pVal[i]=niSbox[pVal[i]>>4][pVal[i]&0x0f];
}

void CAesCrypt::AddRoundKey()
{
	int nAdd=m_nRound*4;
	for(int i=0;i<4;i++)
		for(int j=0;j<4;j++)
			nState[i][j]^=nKeyW[j+nAdd][i];
}
void CAesCrypt::ShiftRows()
{
	unsigned char nVal;
	// 1- сатрни чапга 1 символ сурамиз;
	nVal=nState[1][0];
	nState[1][0]=nState[1][1];
	nState[1][1]=nState[1][2];
	nState[1][2]=nState[1][3];
	nState[1][3]=nVal;
	// 2- сатрни чапга 2 символ сурамиз;
	nVal=nState[2][0];
	nState[2][0]=nState[2][2];
	nState[2][2]=nVal;
	nVal=nState[2][1];
	nState[2][1]=nState[2][3];
	nState[2][3]=nVal;
	// 3- сатрни чапга 3 символ сурамиз;
	nVal=nState[3][3];
	nState[3][3]=nState[3][2];
	nState[3][2]=nState[3][1];
	nState[3][1]=nState[3][0];
	nState[3][0]=nVal;
}
void CAesCrypt::InvShiftRows()
{
	unsigned char nVal;
	// 1- сатрни унгга 1 символ сурамиз;
	nVal=nState[1][3];
	nState[1][3]=nState[1][2];
	nState[1][2]=nState[1][1];
	nState[1][1]=nState[1][0];
	nState[1][0]=nVal;
	// 2- сатрни унгга 2 символ сурамиз;
	nVal=nState[2][0];
	nState[2][0]=nState[2][2];
	nState[2][2]=nVal;
	nVal=nState[2][1];
	nState[2][1]=nState[2][3];
	nState[2][3]=nVal;
	// 3- сатрни унгга 3 символ сурамиз;
	nVal=nState[3][0];
	nState[3][0]=nState[3][1];
	nState[3][1]=nState[3][2];
	nState[3][2]=nState[3][3];
	nState[3][3]=nVal;
}

void CAesCrypt::MixColumns()
{
	for (int i=0;i<16;i++)
			((unsigned char*)nTmpState)[i]=((unsigned char*)nState)[i];

	for (int c=0;c<4;c++)
	{
		nState[0][c]=GF_Mul(nTmpState[0][c],0x02) ^ GF_Mul(nTmpState[1][c],0x03) ^ GF_Mul(nTmpState[2][c],0x01) ^ GF_Mul(nTmpState[3][c],0x01);
		nState[1][c]=GF_Mul(nTmpState[0][c],0x01) ^ GF_Mul(nTmpState[1][c],0x02) ^ GF_Mul(nTmpState[2][c],0x03) ^ GF_Mul(nTmpState[3][c],0x01);
		nState[2][c]=GF_Mul(nTmpState[0][c],0x01) ^ GF_Mul(nTmpState[1][c],0x01) ^ GF_Mul(nTmpState[2][c],0x02) ^ GF_Mul(nTmpState[3][c],0x03);
		nState[3][c]=GF_Mul(nTmpState[0][c],0x03) ^ GF_Mul(nTmpState[1][c],0x01) ^ GF_Mul(nTmpState[2][c],0x01) ^ GF_Mul(nTmpState[3][c],0x02);
	}
}
void CAesCrypt::InvMixColumns()
{
	for (int i=0;i<16;i++)
			((unsigned char*)nTmpState)[i]=((unsigned char*)nState)[i];

	for (int c=0;c<4;c++)
	{
		nState[0][c]=GF_Mul(nTmpState[0][c],0x0e) ^ GF_Mul(nTmpState[1][c],0x0b) ^ GF_Mul(nTmpState[2][c],0x0d) ^ GF_Mul(nTmpState[3][c],0x09);
		nState[1][c]=GF_Mul(nTmpState[0][c],0x09) ^ GF_Mul(nTmpState[1][c],0x0e) ^ GF_Mul(nTmpState[2][c],0x0b) ^ GF_Mul(nTmpState[3][c],0x0d);
		nState[2][c]=GF_Mul(nTmpState[0][c],0x0d) ^ GF_Mul(nTmpState[1][c],0x09) ^ GF_Mul(nTmpState[2][c],0x0e) ^ GF_Mul(nTmpState[3][c],0x0b);
		nState[3][c]=GF_Mul(nTmpState[0][c],0x0b) ^ GF_Mul(nTmpState[1][c],0x0d) ^ GF_Mul(nTmpState[2][c],0x09) ^ GF_Mul(nTmpState[3][c],0x0e);
	}
}

bool CAesCrypt::SetKey(void * pKey, int nKeyLen)
{
	m_nCycleCount=0;
	m_nKeySize=0;
	switch (nKeyLen)
	{
		case 128:
			m_nCycleCount=10;
			m_nKeySize=4;
			break;
		case 192:
			m_nCycleCount=12;
			m_nKeySize=6;
			break;
		case 256:
			m_nCycleCount=14;
			m_nKeySize=8;
			break;
		default:
			if (m_bDump)
			{
				char sTmp[64];
				sprintf(sTmp,"Error! %d bit key is not supported by AES.",nKeyLen);
				strDump += sTmp;
			}
			return false;
	}
	// бошлангич калитни кучирамиз
	int i;
	for(i=0;i<m_nKeySize*4;i++)
		nKeyW[i/4][i%4]=((unsigned char*)pKey)[i];

	// колган калит сатрларни хисоблаймиз
	unsigned char nKeyRow[4];
	for (int nRow=m_nKeySize;nRow<4*(m_nCycleCount+1);nRow++)
	{
		for(i=0;i<4;i++)
			nKeyRow[i]=nKeyW[nRow-1][i];
		int nDiv=nRow%m_nKeySize;
		if(nDiv==0)
		{
			// Чапга битта устун сурамиз
			unsigned char nTmp=nKeyRow[0];
			nKeyRow[0]=nKeyRow[1];
			nKeyRow[1]=nKeyRow[2];
			nKeyRow[2]=nKeyRow[3];
			nKeyRow[3]=nTmp;

			for(i=0;i<4;i++)
				nKeyRow[i]=nSbox[nKeyRow[i]>>4][nKeyRow[i]&0x0f] ^ nRcon[nRow/m_nKeySize][i]; // Replace By nSbox and do XOR with nRcon

		}
		else if (m_nKeySize>6 && nDiv==4)
				for (i=0;i<4;i++)
					nKeyRow[i]=nSbox[nKeyRow[i]>>4][nKeyRow[i]&0x0f]; // Replace By nSbox
	
		for(i=0;i<4;i++)
			nKeyW[nRow][i]=nKeyW[nRow-m_nKeySize][i] ^ nKeyRow[i];
	}

	if (m_bDump)
	{
		char sTmp[64];
		sprintf(sTmp,"KEYSIZE = %d\n\nKEY= ",nKeyLen);
		DumpHex(sTmp,pKey,nKeyLen/8);
		strDump += "\nRound Subkey Values\n";
		for (int nRow=0;nRow<4*(m_nCycleCount+1);nRow+=4)
		{
			sprintf(sTmp,"RK%02d = ",nRow/4);
			DumpHex(sTmp,&nKeyW[nRow][0],16);
		}
	}
	return true;
}
void CAesCrypt::Crypt(void * pData, void * pCipher)
{
	// берилган маълумотларни State таблицага кучирамиз
	int i,j,n=0;
	for (i=0;i<4;i++)
		for(j=0;j<4;j++)
			nState[j][i]=((unsigned char*)pData)[n++];

	if (m_bDump)
		DumpStateHex("\nIntermediate Ciphertext Values (Encryption)\nPT   = ");

	m_nRound=0;
	AddRoundKey();
	for (m_nRound=1;m_nRound < m_nCycleCount;m_nRound++)
	{
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey();

		if (m_bDump)
		{
			char sTmp[64];
			sprintf(sTmp,"CT%02d = ",m_nRound);
			DumpStateHex(sTmp);
		}
	}
	SubBytes();
	ShiftRows();
	AddRoundKey();

	if (m_bDump)
		DumpStateHex("CT   = ");

	// State таблицаcидаги шифр маълумотни чикиш массивига кучирамиз
	n=0;
	for (i=0;i<4;i++)
		for(j=0;j<4;j++)
			((unsigned char*)pCipher)[n++]=nState[j][i];
}

void CAesCrypt::Decrypt(void * pCipher, void * pData)
{
	// берилган шифр маълумотларни State таблицага кучирамиз
	int i,j,n=0;
	for (i=0;i<4;i++)
		for(j=0;j<4;j++)
			nState[j][i]=((unsigned char*)pCipher)[n++];

	if (m_bDump)
		DumpStateHex("\nIntermediate Ciphertext Values (Decryption)\nCT   = ");

	m_nRound=m_nCycleCount;
	AddRoundKey();
	InvShiftRows();
	InvSubBytes();
	m_nRound--;
	for (;m_nRound>=1;m_nRound--)
	{
		if (m_bDump)
		{
			char sTmp[64];
			sprintf(sTmp,"PT%02d = ",m_nRound);
			DumpStateHex(sTmp);
		}
		AddRoundKey();
		InvMixColumns();
		InvShiftRows();
		InvSubBytes();
	}
	AddRoundKey();

	if (m_bDump)
		DumpStateHex("PT   = ");

	// State таблицаcидаги шифр маълумотни кучирамиз
	n=0;
	for (i=0;i<4;i++)
		for(j=0;j<4;j++)
			((unsigned char*)pData)[n++]=nState[j][i];
}

