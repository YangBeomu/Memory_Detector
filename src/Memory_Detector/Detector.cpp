#include "pch.h"
#include "Detector.h"

using namespace std;
using namespace core;

Detector::Detector(const std::tstring process)
	: processName_(process) {
	if ((processHandle_ = GetProcessHandle()) == nullptr) throw runtime_error("Failed to get process handle.");
	if ((processBinaryPath_ = GetProcessBinaryPath()).empty()) throw runtime_error("Failed to get process binary path.");

	auto buffer = ReadBinary();
	if (buffer.empty()) throw runtime_error("Failed to read binary.");

	//HASH
	{
		//auto buffer = ReadBinary();
		//if (buffer.empty()) throw runtime_error("Failed to read binary.");

		auto binaryHash = CalcHash(buffer.data(), buffer.size());
		if (binaryHash.empty()) throw runtime_error("Failed to calculate binary hash.");

		processBinaryHash_ = binaryHash;
	}

	//SECTION
	textSectionBinary_ = GetSectionBinary(buffer, Detector::Section::TEXT);
	if (textSectionBinary_.empty()) throw runtime_error("Failed to get section binary");

	//DLL
	{
		HANDLE handle{};
		core::ST_PROCESSINFO pi{};

		try {
			if (!core::CreateProcess(processBinaryPath_.c_str(), 0, 0, &pi)) throw runtime_error("Failed to create process.");

			if ((handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pi.dwProcessId)) == INVALID_HANDLE_VALUE)
				throw runtime_error("Failed to open process.");

			::Sleep(100);

			if ((dllList_ = GetDllList(handle)).empty()) throw runtime_error("Failed to get dll list.");

			core::TerminateProcess(pi.hProcess);
			system("cls");
			core::CloseProcessHandle(pi.hProcess);

		}
		catch (const exception& e) {
			if (pi.hProcess) {
				core::TerminateProcess(pi.hProcess);
				core::CloseProcessHandle(pi.hProcess);
			}

			throw e;
		}
	}

	//IAT
	{
		try {
			//auto buffer = ReadBinary();
			//if (buffer.empty()) throw runtime_error("Failed to read binary.");
			iatInfo_ = GetIAT(buffer.data());
			if (iatInfo_.empty()) throw runtime_error("Failed to get iat.");
		}
		catch (const exception& e) {
			throw e;
		}
	}

	//THREAD
	workerThread_ = std::thread(&Detector::WorkerFunc, this);
}

Detector::~Detector() {
	if (workerThread_.joinable()) {
		stat_ = STATUS_ENDED;
		Play();
		workerThread_.join();
	}
}

//utility
vector<BYTE> Detector::ReadBinary() {
	vector<BYTE> ret{};
	HANDLE handle{};

	try {
		if ((handle = core::CreateFile(processBinaryPath_.c_str(), core::GENERIC_READ_, core::E_FILE_DISPOSITION::OPEN_EXISTING_, NULL)) == INVALID_HANDLE_VALUE)
			throw runtime_error("Failed to open binary.");

		QWORD binarySize = core::GetFileSize(handle);
		ret.resize(binarySize);

		DWORD readed{};

		if (!core::ReadFile(handle, ret.data(), binarySize, &readed))
			throw runtime_error("Failed to read binary.");
	}
	catch (const exception& e) {
		WarningMsg(string("<ReadBinary> ").append(e.what()));
	}

	if (handle) core::CloseFile(handle);

	return ret;
}

//process
HANDLE Detector::GetProcessHandle() {
	HANDLE handle{};

	vector<ST_PROCESS_INFO> vec;

	if (core::EnumProcesses(processName_, vec) > 0 && !vec.empty()) {
		DWORD pid = vec[0].dwPID;
		handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	}

	return handle;
}

tstring Detector::GetProcessBinaryPath() {
	WCHAR tempPath[MAX_PATH];

	GetModuleFileNameEx(processHandle_, nullptr, tempPath, MAX_PATH);

	return tempPath;
}

//hash
vector<BYTE> Detector::CalcHash(PBYTE buffer, uint bufferSize) {
	vector<BYTE> ret(SHA256_DIGEST_LENGTH, 0);
	EVP_MD_CTX* ctx = EVP_MD_CTX_new(); // Create a new EVP_MD_CTX
	const EVP_MD* md = EVP_sha256();    // Specify SHA256 algorithm

	try {
		if (buffer == nullptr || bufferSize == 0) throw runtime_error("Invalid buffer or size.");
		uchar hash[SHA256_DIGEST_LENGTH]{};

		if (!ctx) throw runtime_error("Failed to create EVP_MD_CTX");
		if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) throw runtime_error("Failed to initialize digest");
		if (EVP_DigestUpdate(ctx, buffer, bufferSize) != 1) throw runtime_error("Failed to update digest");
		if (EVP_DigestFinal_ex(ctx, hash, nullptr) != 1) throw runtime_error("Failed to finalize digest");

		memcpy(ret.data(), hash, sizeof(hash));
	}
	catch (const exception& e) {
		WarningMsg(string("<CalcHash> ").append(e.what()));
	}
	EVP_MD_CTX_free(ctx); // Free the EVP_MD_CTX
	return ret;
}

//section
std::vector<BYTE> Detector::GetSectionBinary(vector<BYTE>& binary, const Detector::Section& sc) {
	vector<BYTE> ret{};

	try {
		switch (sc) {
		case Detector::Section::TEXT: {
			HMODULE hMods[MODS_COUNT]{};

			DWORD needed{};
			if (!EnumProcessModulesEx(processHandle_, hMods, sizeof(hMods), &needed, 0))
				throw runtime_error("Failed to get modules.");

			MODULEINFO mi{};

			if (!GetModuleInformation(processHandle_, hMods[0], &mi, sizeof(mi)))
				throw runtime_error("Failed to get module info.");

			ret.resize(mi.SizeOfImage);
			SIZE_T readed{};

			if (!ReadProcessMemory(processHandle_, hMods[0], ret.data(), ret.size(), &readed))
				throw runtime_error("Failed to read process memory.");

			IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(ret.data());
			IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(ret.data() + dosHeader->e_lfanew);
			IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

			DWORD va = sectionHeader->PointerToRawData; //ntHeader->OptionalHeader.ImageBase + sectionHeader->VirtualAddress;
			DWORD vsz = sectionHeader->Misc.VirtualSize;

			ret.clear();
			ret.resize(vsz);

			if (!ReadProcessMemory(processHandle_, hMods[0] + va, ret.data(), vsz, &readed))
				throw runtime_error("Failed to read process memory.");

		}
		break;
		default: {

		}
		break;
		}
	}
	catch (const exception& e) {
		WarningMsg(string("<GetSectionBinary> ").append(e.what()));
	}

	return ret;
}

//dll
vector<tstring> Detector::GetDllList(HANDLE handle) {
	vector<tstring> ret{};

	try {
		HMODULE hMods[MODS_COUNT]{};
		DWORD cbNeeded{};

		if (!EnumProcessModulesEx(handle, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
			throw runtime_error("Failed to enumerate process modules.");

		//check load dll
		for (unsigned int i = 1; i < (cbNeeded / sizeof(HMODULE)); i++) {
			TCHAR szModName[MAX_PATH]{};

			if (GetModuleBaseName(handle, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
				ret.push_back(szModName);
		}
	}
	catch (const exception& e) {
		WarningMsg(string("<GetDLLList> ").append(e.what()));
	}

	return ret;
}

//logging
void Detector::WarningMsg(const string& msg) {
	cerr << "[Detector]" << msg << endl;
}

void Detector::ErrorMsg(const string& msg) {
	cerr << "[Detector]" << msg << endl;
	exit(1);
}

//control
void Detector::Play() {
	cv_.notify_all();
}

void Detector::Pause() {
	unique_lock<mutex> lck(statusMtx_);
	cv_.wait(lck);
}

void Detector::Run() {
	stat_ = STATUS_RUNNING;

	Play();
}

void Detector::Stop() {
	unique_lock<mutex> lck(dataMtx_);

	stat_ = STATUS_STOPPED;
}

void Detector::WorkerFunc() {
	while (1) {
		try {
			switch (stat_) {
			case STATUS_IDLE: {
				Pause();
				break;
			}
			case STATUS_RUNNING: {
				if (!CompareDLLs());
				if (!CompareIAT());
				break;
			}
			case STATUS_STOPPED: {
				Pause();
				break;
			}
			case STATUS_ENDED: {
				return;
				break;
			}
			case STATUS_ERROR: {

				break;
			}
			default:
				break;
			}
		}
		catch (const exception& e) {
			ErrorMsg(string("<WorkerFunc> ").append(e.what()));
		}
	}
}



DWORD Detector::CalcRVA(const IMAGE_NT_HEADERS* ntHeader, const DWORD& RVA) {
	auto* section = IMAGE_FIRST_SECTION(ntHeader);

	DWORD ret{};

	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i, ++section) {
		DWORD va = section->VirtualAddress;
		DWORD vsz = section->Misc.VirtualSize;

		if (RVA >= va && RVA < va + vsz) {
			ret = RVA - va + section->PointerToRawData;
			break;
		}
	}

	return ret;
}

//map<tstring, vector<tstring>> Detector::GetIAT(core::CPEParser& parser) {
//	map<tstring, vector<tstring>> ret{};
//
//	try {
//		if (!parser.Parse(processBinaryPath_)) throw runtime_error("Failed to parse PE file.");
//
//		std::vector<core::ST_IMPORT_FUNC> imports{};
//		
//		if (parser.GetImportFunction(imports) != EC_SUCCESS)
//			throw runtime_error("Failed to get import function");
//		
//		for (const auto& item : imports) {
//			tstring moduleName(item.strModuleName.begin(), item.strModuleName.end());
//			tstring funcName(item.strFuncName.begin(), item.strFuncName.end());
//
//			ret[moduleName].push_back(funcName);
//		}
//	}
//	catch (const std::exception& e) {
//		WarningMsg(string("<CheckIAT> Failed to call GetIAT: ").append(e.what()));
//	}
//
//	return ret;
//}

map<string, vector<string>> Detector::GetIAT(PBYTE dataPtr, bool dynamic) {
	std::map<std::string, std::vector<std::string>> ret{};

	try {
		auto* dos = (IMAGE_DOS_HEADER*)dataPtr;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)  throw runtime_error("Not a valid PE file (DOS signature).");

		auto* nt = (IMAGE_NT_HEADERS*)((char*)dataPtr + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) throw runtime_error("Not a valid PE file (NT signature).");

		auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (importDir.VirtualAddress == 0) throw runtime_error("No import table found.");

		DWORD importOffset = dynamic ? importDir.VirtualAddress : CalcRVA(nt, importDir.VirtualAddress);
		if (!importOffset) throw runtime_error("Failed to calculate import offset");

		auto* impDesc = (IMAGE_IMPORT_DESCRIPTOR*)(dataPtr + importOffset);

		while (impDesc->Name) {
			DWORD nameRVA = impDesc->Name;
			string dllName{};

			DWORD nameOffset = dynamic ? nameRVA : CalcRVA(nt, nameRVA);
			if (!nameOffset) throw runtime_error("Failed to calculate name offset");

			dllName = reinterpret_cast<char*>(dataPtr + nameOffset);

			DWORD thunkRVA = impDesc->OriginalFirstThunk ? impDesc->OriginalFirstThunk : impDesc->FirstThunk;
			if (thunkRVA == 0) {
				++impDesc;
				continue;
			}

			DWORD thunkOffset = dynamic ? thunkRVA : CalcRVA(nt, thunkRVA);
			if (!thunkOffset) {
				++impDesc;
				continue;
			}

			auto* thunk = (IMAGE_THUNK_DATA*)(dataPtr + thunkOffset);

			while (thunk->u1.AddressOfData) {
				if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
					DWORD hintNameRVA = thunk->u1.AddressOfData;
					DWORD hintNameOffset = dynamic ? hintNameRVA : CalcRVA(nt, hintNameRVA);

					if (hintNameOffset) {
						auto* importByName = (IMAGE_IMPORT_BY_NAME*)(dataPtr + hintNameOffset);

						ret[dllName].push_back(importByName->Name);
					}
				}
				else {
					// Import by ordinal
					ret[dllName].push_back(std::to_string(thunk->u1.Ordinal & 0xFFFF));
				}

				++thunk;
			}
			++impDesc;
		}
	}
	catch (const std::exception& e) {
		WarningMsg(string("<CheckIAT> Failed to call GetIAT: ").append(e.what()));
	}

	return ret;
}

set<tstring> Detector::GetEAT(core::CPEParser& parser) {
	set<tstring> ret{};

	try {
		if (!parser.Parse(processBinaryPath_)) throw runtime_error("Failed to parse PE file.");

		std::vector<core::ST_EXPORT_FUNC> exports{};

		if (parser.GetExportFunction(exports) != EC_SUCCESS)
			throw runtime_error("Failed to get export function");

		for (const auto& item : exports)
			ret.insert(tstring(item.strFuncName.begin(), item.strFuncName.end()));
	}
	catch (const std::exception& e) {
		WarningMsg(string("<CheckIAT> Failed to call GetEAT: ").append(e.what()));
	}

	return ret;
}

void Detector::PrintHash() {
	for (const auto& byte : processBinaryHash_)
		printf("%02x", byte);

	cout << endl;
}

bool Detector::CompareHash(const vector<BYTE>& hash) {
	try {
		if (processBinaryHash_.empty()) throw runtime_error("process binary hash is empty.");

		//Compare
		if (hash != processBinaryHash_)
			return false;

	}
	catch (const exception& e) {
		WarningMsg(string("<CompareHash> ").append(e.what()));
		return false;
	}

	return true;
}

bool Detector::CompareDLLs() {
	HMODULE hMods[MODS_COUNT]{};
	DWORD cbNeeded{};

	try {
		if (dllList_.empty()) return false;

		vector<tstring> cmpDllList = GetDllList(processHandle_);

		for (int i = 0; i < cmpDllList.size(); i++) {
			bool cmpRet = false;

			for (int j = 0; j < dllList_.size(); j++) {
				if (cmpDllList[i] == dllList_[j]) {
					cmpRet = true;
					break;
				}
			}

			if (!cmpRet) {
				wcout << "Other DLL : ";
				wcout << cmpDllList.at(i) << endl;
				break;
			}
		}

		if (dllList_ != cmpDllList) {
			cout << "DLL list mismatch!" << endl;
			return false;
		}
	}
	catch (const exception& e) {
		ErrorMsg(string("<CompareDLLs> ").append(e.what()));
	}

	return true;
}

bool Detector::CompareIAT() {
	HMODULE hMods[MODS_COUNT]{};
	DWORD cbNeeded{};

	try {
		if (iatInfo_.empty()) return false;

		if (!EnumProcessModulesEx(processHandle_, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
			throw runtime_error("Failed to enumerate process modules.");

		MODULEINFO moduleInfo{};

		if (!GetModuleInformation(processHandle_, hMods[0], &moduleInfo, sizeof(moduleInfo)))
			throw runtime_error("Failed to get module information.");

		std::vector<BYTE> buffer(moduleInfo.SizeOfImage, 0);
		SIZE_T readed{};


		if (!ReadProcessMemory(processHandle_, hMods[0], buffer.data(), buffer.size(), &readed))
			throw runtime_error("Failed to read process memory.");

		auto dpIATInfo = GetIAT(buffer.data(), true);
		if (dpIATInfo.empty()) throw runtime_error("Failed to get iat ");

		if (dpIATInfo != iatInfo_) {
			cout << "[WARNING] Wrong type of iAT etected!" << endl;
			return false;
		}
	}
	catch (const exception& e) {
		ErrorMsg(string("<CompareIAT> ").append(e.what()));
	}

	return true;
}

void Detector::PrintDLLs() {
	if (dllList_.empty()) return;

	for (const auto& dll : dllList_) {
		wcout << dll.c_str() << endl;
	}
}

void Detector::PrintIAT() {
	if (iatInfo_.empty()) return;

	for (const auto& info : iatInfo_)
		cout << info.first << endl;
}

void Detector::test() {
	HMODULE hMods[MODS_COUNT]{};

	DWORD needed{};
	try {
		if (!EnumProcessModulesEx(processHandle_, hMods, sizeof(hMods), &needed, 0))
			throw runtime_error("Failed to get modules.");


		//mi
		MODULEINFO mi{};

		if (!GetModuleInformation(processHandle_, hMods[0], &mi, sizeof(mi)))
			throw runtime_error("Failed to get module info.");

		cout << "entry point : " << mi.EntryPoint << endl;
		cout << "mi.lpBaseOfDll : " << mi.lpBaseOfDll << endl;
		cout << "mi.SizeOfImage : " << mi.SizeOfImage << endl;

		//bi
		MEMORY_BASIC_INFORMATION bi{};

		SIZE_T size = VirtualQueryEx(processHandle_, hMods[0], &bi, sizeof(bi));
		cout << "size : " << size << endl;
		{
			cout << "MEMORY_BASIC_INFORMATION:" << endl;
			cout << "  BaseAddress: 0x" << hex << bi.BaseAddress << dec << endl;
			cout << "  AllocationBase: 0x" << hex << bi.AllocationBase << dec << endl;
			cout << "  AllocationProtect: 0x" << hex << bi.AllocationProtect << dec << endl;
#if defined(_WIN64)
			cout << "  PartitionId: " << bi.PartitionId << endl;
#endif
			cout << "  RegionSize: 0x" << hex << bi.RegionSize << dec << " (" << bi.RegionSize << " bytes)" << endl;
			cout << "  State: 0x" << hex << bi.State << dec << endl;
			cout << "  Protect: 0x" << hex << bi.Protect << dec << endl;
			cout << "  Type: 0x" << hex << bi.Type << dec << endl;
		}

		//ci
		vector<BYTE> buffer(mi.SizeOfImage);
		SIZE_T readed{};

		if (ReadProcessMemory(processHandle_, hMods[0], buffer.data(), buffer.size(), &readed)) {

			IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
			IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.data() + dosHeader->e_lfanew);
			IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

			DWORD va = sectionHeader->PointerToRawData; //ntHeader->OptionalHeader.ImageBase + sectionHeader->VirtualAddress;
			DWORD vsz = sectionHeader->Misc.VirtualSize;

			buffer.clear();
			buffer.resize(vsz);

			if (ReadProcessMemory(processHandle_, hMods[0] + va, buffer.data(), vsz, &readed)) {
				if (buffer == textSectionBinary_) {
					cout << "Same!" << endl;
				}
			}
		}
	}
	catch (const exception& e) {
		WarningMsg(string("<test> ").append(e.what()));
	}
}