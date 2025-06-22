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
		DEBUG = 10,    // 디버그 정보 섹션
		SECTION_COUNT
	};

	static constexpr const char* sectionList_[] = {
		(".text"),   // TEXT
		(".rdata"),  // RDATA
		(".data"),   // DATA
		(".bss"),    // BSS
		(".idata"),  // IDATA
		(".edata"),  // EDATA
		(".pdata"),  // PDATA
		(".rsrc"),   // RSRC
		(".reloc"),  // RELOC
		(".tls"),    // TLS
		(".debug"),  // DEBUG
	};

	static constexpr const TCHAR* exceptionDllList_[] = {
		_T("apphelp.dll"),
	};

	struct LogInformation {
		uint64_t startTimestamp_{};
		uint64_t currentTimestamp_{};

		std::tstring processName_{};
		std::tstring processBinaryPath_{};
		std::vector<BYTE> processBinaryHash_{};

		std::map<Section, std::vector<BYTE>> sectionHashs_{};
		std::map<Section, std::vector<BYTE>> processSectionHashs_{};

		std::vector<std::tstring> dllList_{};
		std::vector<std::tstring> processDllList_{};

		std::map <std::string, std::vector<std::string>> iatInfo_{};
		std::map <std::string, std::vector<std::string>> processIatInfo_{};

		bool processRunning{};

		bool isEmpty() const {
			LogInformation li{};

			if (memcmp(this, &li, sizeof(LogInformation)) == 0)
				return true;

			return false;
		}
	};


private:
	struct ProcessInformation {
		HANDLE processHandle_{};
		uint16_t processId_{};

		bool empty() const {
			return processHandle_ == nullptr || processId_ == 0;
		}
	};

	using ProcessInformationPtr = ProcessInformation*;

	//static constexpr int READ_PROCESS_MEMORY_SIZE = 0x4000;
	static constexpr int MODS_COUNT = 0x400;

	//log variable
	uint64_t startTimeStamp_{};
	std::list<LogInformation> logList_{};

	//process variable
	std::tstring processName_{};
	std::tstring processBinaryPath_{};

	ProcessInformation pi_{};
	//sha256
	std::vector<BYTE> processBinaryHash_{}; 

	//.code section variable
	//std::vector<BYTE> textSectionBinary_{};
	std::map<Section, std::vector<BYTE>> sectionHashs_{};
	std::map<Section, std::vector<BYTE>> processSectionHashs_{};

	//dll variable
	std::vector<std::tstring> dllList_{};
	std::vector<std::tstring> processDllList_{};
	//std::vector<std::tstring> otherDllList_{};

	//iat variable
	std::map <std::string, std::vector<std::string>> iatInfo_{}; //dll, functions
	std::map <std::string, std::vector<std::string>> processIatInfo_{};
	//std::map <std::string, std::vector<std::string>> otherIatInfo_{};
	
	std::set<std::tstring> EATInfo_{};

	//Utils
	std::vector<BYTE> ReadBinary();
	HANDLE CreateDummyProcess();
	void DestroyDummyProcess(HANDLE handle);

	//LOG
	uint64_t GetTimeStamp();
	LogInformation GetLogInfo();

	//PROCESS
	ProcessInformation GetProcessInfromation();
	std::tstring GetProcessBinaryPath();
	uint16_t GetProcessID(const std::tstring& processName);

	bool IsProcessRunning(const std::tstring& processName);

	//HASH
	std::vector<BYTE> CalcHash(PBYTE buffer,uint bufferSize);

	//SECTION
	std::vector<Section> GetSectionTypes(std::vector<BYTE>& binary);
	std::vector<BYTE> GetSectionData(HANDLE handle, const Section& sc);
	std::map <Detector::Section, std::vector<BYTE>> GetAllSectionData(HANDLE handle);

	bool CompareSection(const Section sc);

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
	uint32_t workingTick_{};
	std::thread workerThread_{};
	std::mutex dataMtx_{}, statusMtx_{};
	std::condition_variable cv_{};

	void WorkerFunc();

public:
	explicit Detector(const std::tstring process, const uint32_t tick=1000);
	~Detector();
	//STAT
	void Run();
	void Stop();

	bool Detected();

	//HASH
	void PrintHash();
	bool CompareHash(const std::vector<BYTE>& hash);
	
	//DLL
	void PrintDLLs();
	bool CompareDLLs();
	
	//IAT
	void PrintIAT();
	bool CompareIAT();

	//LOG
	LogInformation GetLog();

	void test();
};

