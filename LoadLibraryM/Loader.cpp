// LoadLibraryM.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "LoadLibraryM.h"

int main()
{
    char* szLibName = new char[MAX_PATH + 1];
    std::cin >> szLibName;
    ADDR_M addrLibBase = 0;
    BOOL bResult = LoadLibraryM(szLibName, &addrLibBase);
    if (bResult)
        std::cout << "[+] Load library successfully" << std::endl;
    else
        std::cout << "[-] Load library failed!";
}
 