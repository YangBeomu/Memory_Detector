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
		auto binaryHash = CalcHash(buffer.data(), buffer.size());
		if (binaryHash.empty()) throw runtime_error("Failed to calculate binary hash.");

		processBinaryHash_ = binaryHash;
	}

	HANDLE dummyProcHandle = CreateDummyProcess();
	if (dummyProcHandle == NULL) throw runtime_error("Failed to create dummy porcess");

	std::this_thread::sleep_for(std::chrono::milliseconds(100));

	//SECTION 
	{
		try {
			vector<Section> sectionTypes = GetSectionTypes(buffer);
			if (sectionTypes.empty()) throw runtime_error("Failed to call get section names");

			for(Section& st : sectionTypes) {
				auto binary = GetSectionData(dummyProcHandle, st);
				sectionHashs_[st] = CalcHash(binary.data(), binary.size());
			}
		}
		catch (const exception& e) {
			DestroyDummyProcess(dummyProcHandle);
			throw e;
		}
	}

	//DLL
	{
		try {
			if ((dllList_ = GetDllList(dummyProcHandle)).empty()) throw runtime_error("Failed to get dll list.");
		}
		catch (const exception& e) {
			DestroyDummyProcess(dummyProcHandle);
			throw e;
		}
	}

	//IAT
	{
		try {
			iatInfo_ = GetIAT(buffer.data());
			if (iatInfo_.empty()) throw runtime_error("Failed to get iat.");
		}
		catch (const exception& e) {
			throw e;
		}
	}

	DestroyDummyProcess(dummyProcHandle);

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

HANDLE Detector::CreateDummyProcess() {
	//HANDLE ret{};
	core::ST_PROCESSINFO pi{};

	try {
		if (!core::CreateProcess(processBinaryPath_.c_str(), 0, 0, &pi)) throw runtime_error("Failed to create process.");
	}
	catch (const exception& e) {
		WarningMsg(string("<GetDummyProcess> ").append(e.what()));
	}

	return pi.hProcess;
}

void Detector::DestroyDummyProcess(HANDLE handle) {
	core::TerminateProcess(handle);
	system("cls");
	core::CloseProcessHandle(handle);
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
vector<Detector::Section> Detector::GetSectionTypes(vector<BYTE>& binary) {
	vector<Detector::Section> ret{};

	try {
		IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(binary.data());
		if (dosHeader == nullptr) throw runtime_error("Failed to convert dos header.");

		IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(binary.data() + dosHeader->e_lfanew);
		if (dosHeader == nullptr) throw runtime_error("Failed to convert nt header.");

		IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
		if (dosHeader == nullptr) throw runtime_error("Failed to convert section header.");

		for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
			for (int i = 0; i < sectionToStringAry.size(); i++) {
				if (sectionToStringAry[i].compare(reinterpret_cast<char*>(sectionHeader->Name)) == 0) {
					ret.push_back(Section(i));
					break;
				}
			}

			sectionHeader++;
		}
	}
	catch (const exception& e) {
		WarningMsg(string("<GetSectionTypes> ").append(e.what()));
	}

	return ret;
}

std::vector<BYTE> Detector::GetSectionData(HANDLE handle, const Detector::Section& sc) {
	vector<BYTE> ret{};

	try {
		HMODULE hMods[MODS_COUNT]{};

		DWORD needed{};
		if (!EnumProcessModulesEx(handle, hMods, sizeof(hMods), &needed, 0))
			throw runtime_error("Failed to get modules.");

		MODULEINFO mi{};

		if (!GetModuleInformation(handle, hMods[0], &mi, sizeof(mi)))
			throw runtime_error("Failed to get module info.");

		ret.resize(mi.SizeOfImage);
		SIZE_T readed{};

		if (!ReadProcessMemory(handle, hMods[0], ret.data(), ret.size(), &readed))
			throw runtime_error("Failed to read process memory.");

		IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(ret.data());
		IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(ret.data() + dosHeader->e_lfanew);
		IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

		string scName{};
		bool findSection = false;

		for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
			scName = reinterpret_cast<char*>(sectionHeader->Name);
			if (scName.empty()) throw runtime_error("Failed to convert section name to string");

			if (scName.compare(sectionToStringAry[sc]) == 0) {
				findSection = true;
				break;
			}
				
			sectionHeader++;
		}

		if (!findSection) throw runtime_error("Failed to find section");

		QWORD va = sectionHeader->VirtualAddress;
		DWORD vsz = sectionHeader->Misc.VirtualSize;

		BYTE* realAddr = (reinterpret_cast<BYTE*>(hMods[0]) + va);

		ret.clear();
		ret.resize(vsz);

		
		if (!ReadProcessMemory(handle, realAddr, ret.data(), vsz, &readed)) {
			cout << ::GetLastError() << endl;
			throw runtime_error("Failed to read process memory.");
		}
	}
	catch (const exception& e) {
		WarningMsg(string("<GetSectionBinary> ").append(e.what()));
		ret.clear();
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

bool Detector::SectionCompare() {
	HMODULE hMods[MODS_COUNT]{};

	DWORD needed{};
	try {
		for(const auto& sh : sectionHashs_) {
			auto section = GetSectionData(processHandle_, sh.first);
			auto hash = CalcHash(section.data(), section.size());
			if (hash != sh.second) {
				return false;
			}
		}
	}
	catch (const exception& e) {
		WarningMsg(string("<test> ").append(e.what()));
	}

	return true;
}


void Detector::Test() {
	if (!SectionCompare()) cout << "!!!!" << endl;
}