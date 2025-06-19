#pragma once

class Detector
{
protected:
	enum status {
		STATUS_IDLE = 0,
		STATUS_RUNNING = 1,
		STATUS_STOPPED = 2,
		STATUS_ENDED = 3,
		STATUS_ERROR = 4,
		STATUS_MAX = 5
	};

	enum Section {
		TEXT = 0,     // 실행 코드가 포함된 섹션
		RDATA = 1,    // 읽기 전용 데이터 섹션
		DATA = 2,     // 초기화된 데이터 섹션
		BSS = 3,      // 초기화되지 않은 데이터 섹션
		IDATA = 4,    // 가져온 함수 정보(Import) 섹션
		EDATA = 5,    // 내보낸 함수 정보(Export) 섹션
		PDATA = 6,    // 예외 처리 정보 섹션
		RSRC = 7,     // 리소스 섹션
		RELOC = 8,    // 재배치 정보 섹션
		TLS = 9,      // 스레드 로컬 스토리지 섹션
		DEBUG = 10    // 디버그 정보 섹션
	};

private:
	//static constexpr int READ_PROCESS_MEMORY_SIZE = 0x4000;
	static constexpr int MODS_COUNT = 0x400;

	std::tstring processName_{};
	HANDLE processHandle_{};
	std::tstring processBinaryPath_{};

	//sha256
	std::vector<BYTE> processBinaryHash_{}; 

	//.code section variable
	std::vector<BYTE> textSectionBinary_{};

	//dll variable
	std::vector<std::tstring> dllList_{};

	//iat variable
	std::map <std::string, std::vector<std::string>> iatInfo_{}; //dll, functions
	std::set<std::tstring> EATInfo_{};

	//Utils
	std::vector<BYTE> ReadBinary();

	//PROCESS INFO
	HANDLE GetProcessHandle() ;
	std::tstring GetProcessBinaryPath();

	//HASH
	std::vector<BYTE> CalcHash(PBYTE buffer,uint bufferSize);

	//CODE SECTION
	std::vector<BYTE> GetSectionBinary(std::vector<BYTE>& binary, const Section& sc);

	//DLL
	std::vector<std::tstring> GetDllList(HANDLE handle);
	
	//IAT
	DWORD CalcRVA(const IMAGE_NT_HEADERS* ntHeader, const DWORD& RVA);

	std::map<std::string, std::vector<std::string>> GetIAT(PBYTE dataPtr,bool dynamic = false); //iatInfo_<dllName, functionNames>
	std::set<std::tstring> GetEAT(core::CPEParser& parser);

	//Logging
	void WarningMsg(const std::string& msg);
	void ErrorMsg(const std::string& msg);

	//control
	Detector::status stat_{ STATUS_IDLE };

	void Play();
	void Pause();
	void End();

protected:
	//thread relative variables
	std::thread workerThread_{};
	std::mutex dataMtx_{}, statusMtx_{};
	std::condition_variable cv_{};

	void WorkerFunc();

public:
	explicit Detector(const std::tstring process);
	~Detector();

	void Run();
	void Stop();

	void PrintHash();
	bool CompareHash(const std::vector<BYTE>& hash);
	
	void PrintDLLs();
	bool CompareDLLs();
	
	void PrintIAT();
	bool CompareIAT();

	void test();
};

