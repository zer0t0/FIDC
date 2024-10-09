#include <windows.h>
#include <TlHelp32.h>		//�������̿��պ������������windows.h����
#include <stdio.h>
#include <tchar.h>			//InjectDll��������

#define MAX_BYTE 100
#define MAX_Pid  100


WCHAR* AsciiToUnicode(char* szBuffer)
{
	int i;
	WCHAR szwBuffer[MAX_BYTE];
	int szBuffer_len = strlen(szBuffer);
	int tmp_szBuffer_len = szBuffer_len;

	//��ʼ��szwBuffer
	for (i = 0; i < MAX_BYTE; i++)
	{
		szwBuffer[i] = '\0';
	}

	if (strlen(szBuffer) > (MAX_BYTE - 1) || *szBuffer == NULL)
	{
		MessageBox(0, TEXT("AsciiToUnicode Error"), TEXT("Error!"), NULL);
		return szwBuffer;
	}

	szwBuffer[tmp_szBuffer_len] = '\0';
	tmp_szBuffer_len--;
	while (tmp_szBuffer_len >= 0)
	{
		szwBuffer[tmp_szBuffer_len] = (WCHAR)szBuffer[tmp_szBuffer_len];
		tmp_szBuffer_len--;
	}

	return szwBuffer;
}

BOOL SetProcDebug(HANDLE ProcessHandle)
{
	TOKEN_PRIVILEGES token_p;       //�������ƽṹ

	//��ʼ�����̷������ƾ��
	HANDLE hToken;
	hToken = NULL;

	//�򿪽��̵ķ�������
	if (OpenProcessToken(ProcessHandle, TOKEN_ALL_ACCESS, &hToken))
	{
		token_p.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &token_p.Privileges[0].Luid);     //��ȡ����Ȩ�޵�LUID
		token_p.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &token_p, sizeof(token_p), NULL, NULL);
		CloseHandle(hToken);
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

int* GetProcessID(LPCWSTR ProcessName)
{
	int i;
	int iPid[MAX_Pid];
	BOOL bPRet;				//���̱����ж�
	HANDLE hSnap;			//���̿��վ��
	PROCESSENTRY32 Pe32;		//�������ݽṹ

	//��ʼ��iPid
	for (i = 0; i < MAX_Pid; i++)
	{
		iPid[i] = '\0';
	}

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, TEXT("Error!"), TEXT("CreateToolhelp32Snapshot error"), MB_OK);
	}

	Pe32.dwSize = sizeof(PROCESSENTRY32);
	iPid[0] = 0;
	//��ʼ����
	bPRet = Process32First(hSnap, &Pe32);
	while (bPRet)
	{
		if (lstrcmpW(ProcessName, Pe32.szExeFile) == 0)
		{
			iPid[0]++;
			iPid[iPid[0]] = Pe32.th32ProcessID;
			//return Pe32.th32ProcessID;
		}
		bPRet = Process32Next(hSnap, &Pe32);
	}
	return iPid;
}

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
#ifdef _WIN64
	typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		ULONG CreateThreadFlags,
		SIZE_T ZeroBits,
		SIZE_T StackSize,
		SIZE_T MaximumStackSize,
		LPVOID pUnkown);
#else
	typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		BOOL CreateSuspended,
		DWORD dwStackSize,
		DWORD dw1,
		DWORD dw2,
		LPVOID pUnkown);
#endif
	typedef_ZwCreateThreadEx ZwCreateThreadEx;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	HMODULE hMod = NULL;
	HMODULE hNtdllMod = NULL;
	LPVOID pRemoteBuf = NULL;		//��Ŀ�����������ڴ��ַ
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;
	HANDLE hRemoteThread = NULL;
	DWORD dwStatus = 0;
	char cTmp[100] = { 0 };

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (!hProcess)
	{
		printf("���̴�ʧ��\n");
		return FALSE;
	}

	//��Ŀ�����������dll�ռ�
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
	{
		printf("��������ڴ�ռ�ʧ��\n");
		return FALSE;
	}

	//��dll·��д��������ڴ�ռ�
	if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL))
	{
		printf("д��dll·��ʧ��\n");
		return FALSE;
	}

	hNtdllMod = LoadLibrary(L"ntdll.dll");
	if (hNtdllMod == NULL)
	{
		printf("ntdll.dll��ʧ��\n");
		return FALSE;
	}

	hMod = GetModuleHandle(L"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
	if (pThreadProc == NULL)
	{
		return  FALSE;
	}

	ZwCreateThreadEx = (typedef_ZwCreateThreadEx)GetProcAddress(hNtdllMod, "ZwCreateThreadEx");
	if (ZwCreateThreadEx == NULL)
	{
		printf("ZwCreateThreadEx����\n");
		return FALSE;
	}
	dwStatus = ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pThreadProc, pRemoteBuf, 0, 0, 0, 0, NULL);
	if (hRemoteThread == NULL)
	{
		printf("ע��ʧ��\n\n");
		return FALSE;
	}

	//WaitForSingleObject(hThread, INFINITE);

	//CloseHandle(hThread);
	CloseHandle(hProcess);
	FreeLibrary(hNtdllMod);

	return TRUE;
}

BOOL BeforeInjectDll()
{
	BOOL bRet = FALSE;
	int i;
	char judge[2];
	char szProcName[MAX_BYTE];	//Ascii�������
	WCHAR* tmp_pwProcName;
	WCHAR szwProcName[MAX_BYTE];//���ַ��������
	char szDllName[MAX_BYTE];	//Ascii��Dll·��
	WCHAR* tmp_pwDllName;
	WCHAR szwDllName[MAX_BYTE];	//���ַ���Dll·��
	int* tmp_nPid;
	int nPid[MAX_Pid];			//���̺�
	int n;						//��Ϊ��ʱ�Ľ��̺�
	int PidError[MAX_Pid];
	int PidError_len = 0;
	BOOL bPidError;

	//��ʼ��
	judge[1] = '\0';

	for (i = 0; i < MAX_BYTE; i++)
	{
		szProcName[i] = '\0';
		szwProcName[i] = '\0';
		szDllName[i] = '\0';
		szwDllName[i] = '\0';
	}

	for (i = 0; i < MAX_Pid; i++)
	{
		nPid[i] = 0;
		PidError[i] = 0;
	}

	//ת���ַ���ʽ
	printf("����Ҫע���Dll�ļ�����·��:");
	scanf_s("%s", szDllName, MAX_BYTE);
	tmp_pwDllName = AsciiToUnicode(szDllName);
	for (i = 0; i < MAX_BYTE; i++)
	{
		szwDllName[i] = tmp_pwDllName[i];
	}

	printf("���������(������׺):");
	scanf_s("%s", szProcName, MAX_BYTE);
	tmp_pwProcName = AsciiToUnicode(szProcName);
	for (i = 0; i < MAX_BYTE; i++)
	{
		szwProcName[i] = tmp_pwProcName[i];
	}

	tmp_nPid = GetProcessID(szwProcName);

	for (i = 0; i <= tmp_nPid[0]; i++)
	{
		nPid[i] = tmp_nPid[i];
	}

	if (nPid[0] == 0)
	{
		printf("û���ҵ��ý���\n\n");
		return bRet;
	}
	else if (nPid[0] > 1)
	{
		printf("�ý��̴��ڶ�����Ƿ񶼽���ע��? (����y or n)");
		scanf_s("%s", &judge, 2);		//scanf_s����ʹ��%c
		printf("���ڽ��̺ŷֱ�Ϊ�������е�ͬ������:\n");
		for (i = 1; i <= nPid[0]; i++)
		{
			printf("%d: %d\n", i, nPid[i]);
		}

		if (judge[0] == 'y')
		{
			for (i = 1; i <= nPid[0]; i++)
			{
				bPidError = TRUE;
				bPidError = InjectDll((DWORD)nPid[i], szwDllName);
				if (bPidError == FALSE)
				{
					PidError[PidError_len] = nPid[i];
					PidError_len++;
				}
				else
				{
					//ֻҪ����һ������ע��ɹ��򷵻�TRUE
					bRet = TRUE;
				}
			}
			if (PidError_len != 0)
			{
				printf("���½��̺�ע��ʧ��:\n");
				for (i = 0; i < PidError_len; i++)
				{
					printf("%d\n", PidError[i]);
				}
			}
			else
			{
				printf("ȫ��ע��ɹ�\n\n");
			}
			return bRet;

		}
		else
		{

			printf("\n������Ҫע��Ľ��̺�:");
			scanf_s("%d", &n);
			bPidError = TRUE;
			bPidError = InjectDll((DWORD)n, szwDllName);
			if (bPidError == FALSE)
			{
				printf("ע��ʧ��\n\n");
				return bRet;
			}
			else
			{
				bRet = TRUE;
				printf("ע��ɹ�\n\n");
				return bRet;
			}
		}
	}
	else
	{
		bPidError = TRUE;
		bPidError = InjectDll((DWORD)nPid[1], szwDllName);
		if (bPidError == FALSE)
		{
			printf("ע��ʧ��\n\n");
			return bRet;
		}
		else
		{
			bRet = TRUE;
			printf("ע��ɹ�\n\n");
			return bRet;
		}
	}

}

BOOL UnInjectDll(DWORD dwPid, TCHAR* szDllName)
{
	BOOL bRet;
	HANDLE hSnap;
	MODULEENTRY32 me32;		//ģ����սṹ
	HANDLE hProcess;
	FARPROC pFunAddr;		//FreeLibrary�ĵ�ַ
	HANDLE hThread;

	if (lstrlen(szDllName) == 0 || dwPid == 0)
	{
		return FALSE;
	}

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);

	me32.dwSize = sizeof(me32);
	bRet = Module32First(hSnap, &me32);
	while (bRet)
	{
		if (lstrcmp(szDllName, me32.szExePath) == 0)
		{
			break;
		}
		bRet = Module32Next(hSnap, &me32);
	}
	if (bRet == NULL)
	{
		return FALSE;
	}
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);

	if (hProcess == NULL)
	{
		printf("���̴�ʧ��\n");
		return FALSE;
	}

	pFunAddr = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary");
	if (pFunAddr == NULL)
	{
		return  FALSE;
	}

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFunAddr, me32.hModule, 0, NULL);
	if (hThread == NULL)
	{
		printf("ж��ʧ��\n");
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hSnap);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;

}

BOOL BeforeUnInjectDll()
{
	int i;
	char szProcName[MAX_BYTE];	//Ascii�������
	WCHAR* tmp_pwProcName;
	WCHAR szwProcName[MAX_BYTE];//���ַ��������
	char szDllName[MAX_BYTE];	//Ascii��Dll·��
	WCHAR* tmp_pwDllName;
	WCHAR szwDllName[MAX_BYTE];	//���ַ���Dll·��
	int* tmp_nPid;
	int nPid[MAX_Pid];			//���̺�
	char judge[2];
	int n;						//��Ϊ��ʱ�Ľ��̺�
	int PidError[MAX_Pid];
	int PidError_len = 0;
	BOOL bPidError;
	BOOL bRet = FALSE;


	//��ʼ��
	for (i = 0; i < MAX_BYTE; i++)
	{
		szProcName[i] = '\0';
		szwProcName[i] = '\0';
		szDllName[i] = '\0';
		szwDllName[i] = '\0';
	}

	for (i = 0; i < MAX_Pid; i++)
	{
		nPid[i] = 0;
	}

	//ת���ַ���ʽ
	printf("����Ҫж�ص�Dll�ļ�����·��:");
	scanf_s("%s", szDllName, MAX_BYTE);
	tmp_pwDllName = AsciiToUnicode(szDllName);
	for (i = 0; i < MAX_BYTE; i++)
	{
		szwDllName[i] = tmp_pwDllName[i];
	}

	printf("���������(������׺):");
	scanf_s("%s", szProcName, MAX_BYTE);
	tmp_pwProcName = AsciiToUnicode(szProcName);
	for (i = 0; i < MAX_BYTE; i++)
	{
		szwProcName[i] = tmp_pwProcName[i];
	}

	tmp_nPid = GetProcessID(szwProcName);

	for (i = 0; i <= tmp_nPid[0]; i++)
	{
		nPid[i] = tmp_nPid[i];
	}

	if (nPid[0] == 0)
	{
		printf("û���ҵ��ý���\n\n");
		return bRet;
	}
	else if (nPid[0] > 1)
	{
		printf("�ý��̴��ڶ�����Ƿ������ڸ�dll�򶼽���ж��? (����y or n)");
		scanf_s("%s", &judge, 2);		//scanf_s����ʹ��%c
		printf("���ڽ��̺ŷֱ�Ϊ�������е�ͬ������:\n");
		for (i = 1; i <= nPid[0]; i++)
		{
			printf("%d: %d\n", i, nPid[i]);
		}

		if (judge[0] == 'y')
		{
			for (i = 1; i <= nPid[0]; i++)
			{
				bPidError = TRUE;
				bPidError = UnInjectDll((DWORD)nPid[i], szwDllName);
				if (bPidError == FALSE)
				{
					PidError[PidError_len] = nPid[i];
					PidError_len++;
				}
				else
				{
					//ֻҪ����һ������ע��ɹ��򷵻�TRUE
					bRet = TRUE;
				}
			}
			if (PidError_len != 0)
			{
				printf("���½��̺�ж��ʧ��:\n");
				for (i = 0; i < PidError_len; i++)
				{
					printf("%d\n", PidError[i]);
				}
			}
			else
			{
				printf("ȫ��ж�سɹ�\n\n");
			}
			return bRet;

		}
		else
		{

			printf("\n������Ҫж�صĽ��̺�:");
			scanf_s("%d", &n);
			bPidError = TRUE;
			bPidError = UnInjectDll((DWORD)n, szwDllName);
			if (bPidError == FALSE)
			{
				printf("ж��ʧ��\n\n");
				return bRet;
			}
			else
			{
				bRet = TRUE;
				printf("ж�سɹ�\n\n");
				return bRet;
			}
		}
	}
	else
	{
		bPidError = UnInjectDll((DWORD)nPid[1], szwDllName);
		if (bPidError == FALSE)
		{
			printf("ж��ʧ��\n\n");
			return bRet;
		}
		else
		{
			bRet = TRUE;
			printf("ж�سɹ�\n\n");
			return bRet;
		}
	}
}

int main()
{
	DWORD i;
	char key[2];
	BOOL bRet;


	printf("                                             .:.\n");
	printf("                                             .#.\n");
	printf("                                              **:\n");
	printf("                      ...:::::::....          +**=.\n");
	printf("                  .::  ..... .   .  :::.       :****=.\n");
	printf("                 .      :  : :   :     -.      .******-.\n");
	printf("                 .-    .:..: :.. :..    -.     .=*******=.\n");
	printf("                  :-                   .    ..=**********::..\n");
	printf("                   ..:::::::::-=:...     .=++*###*#*+=##====.\n");
	printf("                              .:        .:-=*#**#=:-::-+.\n");
	printf("                                    .:-+***##*****::--+:.\n");
	printf("                                  .-++=+++=+*+****#++:=:\n");
	printf("                                 :*+***********####*+:.    ..:--:\n");
	printf("                                :**********#***##*+:::--=+++=--:.\n");
	printf("                               .+***********==+***+-+=-:...\n");
	printf("                               -****************:::..\n");
	printf("                 ..            -*************###.\n");
	printf("               ..:=*+*=-.::::-=+**+*********#*+-.\n");
	printf("               .++##*****=+=-:****+*****#%###=.\n");
	printf("               .=#**+****-.  .+********+:=###.\n");
	printf("                .::*#***+.   ==**--*:=:.  ...\n");
	printf("                 .:--===.     .+. ..\n\n\n");


	if (SetProcDebug(GetCurrentProcess()))
	{
		printf("��Ȩ�ɹ�:�����������óɵ���ģʽ\n\n");
	}
	else
	{
		printf("��Ȩʧ��\n\n");
		if (MessageBox(0, TEXT("��Ȩʧ�ܣ��Ƿ��������?"), TEXT("����!"), MB_YESNO) != IDYES)
		{
			return 0;
		}
	}


	while (1)
	{
		printf("\n");
		printf("\t ____________________\n");
		printf("\t|        ѡ��        |\n");
		printf("\t|--------------------|\n");
		printf("\t|-----1.ע��Dll------|\n");
		printf("\t|-----2.ж��Dll------|\n");
		printf("\t|-----3.�˳�   ------|\n");
		printf("\t|____________________|\n");
		printf("\n������Ӧ���ּ�����ѡ��:");

		scanf_s("%s", &key, 2);

		switch (key[0])
		{
		case '1':
			bRet = BeforeInjectDll();
			break;
		case '2':
			bRet = BeforeUnInjectDll();
			break;
		case '3':
			return 0;
			break;
		default:
			printf("û�д�ѡ��!������ѡ��\n\n");
			break;
		}
	}

}