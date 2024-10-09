#include <windows.h>
#include <TlHelp32.h>		//包含进程快照函数，必须放在windows.h后面
#include <stdio.h>
#include <tchar.h>			//InjectDll函数必需

#define MAX_BYTE 100
#define MAX_Pid  100


WCHAR* AsciiToUnicode(char* szBuffer)
{
	int i;
	WCHAR szwBuffer[MAX_BYTE];
	int szBuffer_len = strlen(szBuffer);
	int tmp_szBuffer_len = szBuffer_len;

	//初始化szwBuffer
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
	TOKEN_PRIVILEGES token_p;       //访问令牌结构

	//初始化进程访问令牌句柄
	HANDLE hToken;
	hToken = NULL;

	//打开进程的访问令牌
	if (OpenProcessToken(ProcessHandle, TOKEN_ALL_ACCESS, &hToken))
	{
		token_p.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &token_p.Privileges[0].Luid);     //获取描述权限的LUID
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
	BOOL bPRet;				//进程遍历判断
	HANDLE hSnap;			//进程快照句柄
	PROCESSENTRY32 Pe32;		//进程数据结构

	//初始化iPid
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
	//开始遍历
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
	LPVOID pRemoteBuf = NULL;		//向目标进程申请的内存地址
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;
	HANDLE hRemoteThread = NULL;
	DWORD dwStatus = 0;
	char cTmp[100] = { 0 };

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (!hProcess)
	{
		printf("进程打开失败\n");
		return FALSE;
	}

	//在目标进程中申请dll空间
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
	{
		printf("申请进程内存空间失败\n");
		return FALSE;
	}

	//将dll路径写入申请的内存空间
	if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL))
	{
		printf("写入dll路径失败\n");
		return FALSE;
	}

	hNtdllMod = LoadLibrary(L"ntdll.dll");
	if (hNtdllMod == NULL)
	{
		printf("ntdll.dll打开失败\n");
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
		printf("ZwCreateThreadEx出错\n");
		return FALSE;
	}
	dwStatus = ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pThreadProc, pRemoteBuf, 0, 0, 0, 0, NULL);
	if (hRemoteThread == NULL)
	{
		printf("注入失败\n\n");
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
	char szProcName[MAX_BYTE];	//Ascii版进程名
	WCHAR* tmp_pwProcName;
	WCHAR szwProcName[MAX_BYTE];//宽字符版进程名
	char szDllName[MAX_BYTE];	//Ascii版Dll路径
	WCHAR* tmp_pwDllName;
	WCHAR szwDllName[MAX_BYTE];	//宽字符版Dll路径
	int* tmp_nPid;
	int nPid[MAX_Pid];			//进程号
	int n;						//极为临时的进程号
	int PidError[MAX_Pid];
	int PidError_len = 0;
	BOOL bPidError;

	//初始化
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

	//转换字符格式
	printf("输入要注入的Dll文件绝对路径:");
	scanf_s("%s", szDllName, MAX_BYTE);
	tmp_pwDllName = AsciiToUnicode(szDllName);
	for (i = 0; i < MAX_BYTE; i++)
	{
		szwDllName[i] = tmp_pwDllName[i];
	}

	printf("输入进程名(包含后缀):");
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
		printf("没有找到该进程\n\n");
		return bRet;
	}
	else if (nPid[0] > 1)
	{
		printf("该进程存在多个，是否都进行注入? (输入y or n)");
		scanf_s("%s", &judge, 2);		//scanf_s不能使用%c
		printf("存在进程号分别为以下所列的同名进程:\n");
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
					//只要存在一个进程注入成功则返回TRUE
					bRet = TRUE;
				}
			}
			if (PidError_len != 0)
			{
				printf("以下进程号注入失败:\n");
				for (i = 0; i < PidError_len; i++)
				{
					printf("%d\n", PidError[i]);
				}
			}
			else
			{
				printf("全部注入成功\n\n");
			}
			return bRet;

		}
		else
		{

			printf("\n请输入要注入的进程号:");
			scanf_s("%d", &n);
			bPidError = TRUE;
			bPidError = InjectDll((DWORD)n, szwDllName);
			if (bPidError == FALSE)
			{
				printf("注入失败\n\n");
				return bRet;
			}
			else
			{
				bRet = TRUE;
				printf("注入成功\n\n");
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
			printf("注入失败\n\n");
			return bRet;
		}
		else
		{
			bRet = TRUE;
			printf("注入成功\n\n");
			return bRet;
		}
	}

}

BOOL UnInjectDll(DWORD dwPid, TCHAR* szDllName)
{
	BOOL bRet;
	HANDLE hSnap;
	MODULEENTRY32 me32;		//模块快照结构
	HANDLE hProcess;
	FARPROC pFunAddr;		//FreeLibrary的地址
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
		printf("进程打开失败\n");
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
		printf("卸载失败\n");
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
	char szProcName[MAX_BYTE];	//Ascii版进程名
	WCHAR* tmp_pwProcName;
	WCHAR szwProcName[MAX_BYTE];//宽字符版进程名
	char szDllName[MAX_BYTE];	//Ascii版Dll路径
	WCHAR* tmp_pwDllName;
	WCHAR szwDllName[MAX_BYTE];	//宽字符版Dll路径
	int* tmp_nPid;
	int nPid[MAX_Pid];			//进程号
	char judge[2];
	int n;						//极为临时的进程号
	int PidError[MAX_Pid];
	int PidError_len = 0;
	BOOL bPidError;
	BOOL bRet = FALSE;


	//初始化
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

	//转换字符格式
	printf("输入要卸载的Dll文件绝对路径:");
	scanf_s("%s", szDllName, MAX_BYTE);
	tmp_pwDllName = AsciiToUnicode(szDllName);
	for (i = 0; i < MAX_BYTE; i++)
	{
		szwDllName[i] = tmp_pwDllName[i];
	}

	printf("输入进程名(包含后缀):");
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
		printf("没有找到该进程\n\n");
		return bRet;
	}
	else if (nPid[0] > 1)
	{
		printf("该进程存在多个，是否若存在该dll则都进行卸载? (输入y or n)");
		scanf_s("%s", &judge, 2);		//scanf_s不能使用%c
		printf("存在进程号分别为以下所列的同名进程:\n");
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
					//只要存在一个进程注入成功则返回TRUE
					bRet = TRUE;
				}
			}
			if (PidError_len != 0)
			{
				printf("以下进程号卸载失败:\n");
				for (i = 0; i < PidError_len; i++)
				{
					printf("%d\n", PidError[i]);
				}
			}
			else
			{
				printf("全部卸载成功\n\n");
			}
			return bRet;

		}
		else
		{

			printf("\n请输入要卸载的进程号:");
			scanf_s("%d", &n);
			bPidError = TRUE;
			bPidError = UnInjectDll((DWORD)n, szwDllName);
			if (bPidError == FALSE)
			{
				printf("卸载失败\n\n");
				return bRet;
			}
			else
			{
				bRet = TRUE;
				printf("卸载成功\n\n");
				return bRet;
			}
		}
	}
	else
	{
		bPidError = UnInjectDll((DWORD)nPid[1], szwDllName);
		if (bPidError == FALSE)
		{
			printf("卸载失败\n\n");
			return bRet;
		}
		else
		{
			bRet = TRUE;
			printf("卸载成功\n\n");
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
		printf("提权成功:本进程已设置成调试模式\n\n");
	}
	else
	{
		printf("提权失败\n\n");
		if (MessageBox(0, TEXT("提权失败，是否继续运行?"), TEXT("警告!"), MB_YESNO) != IDYES)
		{
			return 0;
		}
	}


	while (1)
	{
		printf("\n");
		printf("\t ____________________\n");
		printf("\t|        选项        |\n");
		printf("\t|--------------------|\n");
		printf("\t|-----1.注入Dll------|\n");
		printf("\t|-----2.卸载Dll------|\n");
		printf("\t|-----3.退出   ------|\n");
		printf("\t|____________________|\n");
		printf("\n输入相应数字键进行选择:");

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
			printf("没有此选项!请重新选择\n\n");
			break;
		}
	}

}