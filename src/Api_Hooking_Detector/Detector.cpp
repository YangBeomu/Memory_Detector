#include "pch.h"
#include "Detector.h"

using namespace std;
using namespace core;

Detector::Detector(const std::tstring process)
	: processName_(process) {

	if ((processHandle_ = GetProcessHandle()) == nullptr) throw runtime_error("Failed to get process handle.");
	if ((processBinaryPath_ = GetProcessBinaryPath()).empty()) throw runtime_error("Failed to get process binary path.");
	if ((dllList_ = GetDLLs()).empty()) throw runtime_error("Failed to get dll list.");

	//IAT
	HANDLE binaryHandle{};

	if ((binaryHandle = core::CreateFile(processBinaryPath_.c_str(), core::GENERIC_READ_, core::E_FILE_DISPOSITION::OPEN_EXISTING_, NULL)) == INVALID_HANDLE_VALUE)
		throw runtime_error("Failed to open binary.");

	int binarySize = core::GetFileSize(binaryHandle);
	unique_ptr<BYTE> buffer(new BYTE[binarySize]);

	DWORD readed{};

	if (!core::ReadFile(binaryHandle, buffer.get(), binarySize, &readed))
		throw runtime_error("Failed to read binary.");

	core::CloseFile(binaryHandle);

	iatInfo_ = GetIAT(buffer.get());

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

//dll
vector<tstring> Detector::GetDLLs() {
	vector<tstring> ret{};

	try {
		HMODULE hMods[MODS_COUNT]{};
		DWORD cbNeeded{};
		HANDLE handle{};

		if ((handle = core::LoadLibrary(processBinaryPath_.c_str())) == INVALID_HANDLE_VALUE)
			throw runtime_error("Failed to load library.");

		if (!EnumProcessModules(handle, hMods, sizeof(hMods), &cbNeeded))
			throw runtime_error("Failed to enumerate modules.");

		TCHAR modName[MAX_PATH]{};

		for (int i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
			if (GetModuleBaseName(handle, hMods[i], modName, sizeof(modName)))
				ret.push_back(modName);
		}

		CloseHandle(handle);
	}
	catch (const exception& e) {
		WarningMsg(string("<GetDLL> ").append(e.what()));
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
		if (importOffset == 0) throw runtime_error("Failed to find import directory in sections.");

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
					//std::cout << "  Ordinal: " << (thunk->u1.Ordinal & 0xFFFF) << std::endl;
					ret[dllName].push_back(reinterpret_cast<char*>(thunk->u1.Ordinal & 0xFFFF));
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

bool Detector::CompareDLL() {
	HMODULE hMods[MODS_COUNT]{};
	DWORD cbNeeded{};

	try {
		if (!EnumProcessModulesEx(processHandle_, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
			throw runtime_error("Failed to enumerate process modules.");



		//check load dll
		for (unsigned int i = 1; i < (cbNeeded / sizeof(HMODULE)); i++) {
			TCHAR szModName[MAX_PATH]{};

			if (GetModuleBaseName(processHandle_, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {

			}
		}
	}
	catch (const exception& e) {
		WarningMsg(string("<CompareDLL> ").append(e.what()));
		return false;
	}

	return true;
}

bool Detector::CompareIAT() {
	HMODULE hMods[MODS_COUNT]{};
	DWORD cbNeeded{};

	try {
		if (!EnumProcessModulesEx(processHandle_, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
			throw runtime_error("Failed to enumerate process modules.");

		unique_ptr<BYTE> buffer(new BYTE[READ_PROCESS_MEMORY_SIZE]);
		SIZE_T readed{};

		if (!ReadProcessMemory(processHandle_, hMods[0], buffer.get(), READ_PROCESS_MEMORY_SIZE, &readed))
			throw runtime_error("Failed to read process memory");

		auto test = GetIAT(buffer.get(), true);
		if (test.empty()) throw runtime_error("Failed to get iat ");
	}
	catch (const exception& e) {
		WarningMsg(string("<CompareIAT> ").append(e.what()));
		return false;
	}

	return true;
}

void Detector::PrintIAT() {
	core::CPEParser parser{};

	CompareIAT();

	if (iatInfo_.empty()) return;

	cout << endl;
}