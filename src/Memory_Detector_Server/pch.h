#pragma once  

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>  
#include <fstream>
#include <string> 
#include <string_view>
#include <chrono>

#include <vector>
#include <set>
#include <map>

#include <thread>
#include <mutex>
#include <condition_variable>

#include <tchar.h>

#include <Windows.h>
#include <winnt.h>
#include <imagehlp.h>
#include <Psapi.h>
#include <tlhelp32.h>

#include "cppcore.h"

#include "network_headers/ip.h"

#include "openssl/evp.h" // Include the EVP API
#include "openssl/sha.h"

#pragma comment(lib, "cppcore.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

