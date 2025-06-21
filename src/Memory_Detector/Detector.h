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
		TEXT = 0,     // ���� �ڵ尡 ���Ե� ����
		RDATA = 1,    // �б� ���� ������ ����
		DATA = 2,     // �ʱ�ȭ�� ������ ����
		BSS = 3,      // �ʱ�ȭ���� ���� ������ ����
		IDATA = 4,    // ������ �Լ� ����(Import) ����
		EDATA = 5,    // ������ �Լ� ����(Export) ����
		PDATA = 6,    // ���� ó�� ���� ����
		RSRC = 7,     // ���ҽ� ����
		RELOC = 8,    // ���ġ ���� ����
		TLS = 9,      // ������ ���� ���丮�� ����
		DEBUG = 10,    // ����� ���� ����
		SECTION_COUNT
	};

	std::vector<std::string> sectionToStringAry {
	".text",   // TEXT
	".rdata",  // RDATA
	".data",   // DATA
	".bss",    // BSS
	".idata",  // IDATA
	".edata",  // EDATA
	".pdata",  // PDATA
	".rsrc",   // RSRC
	".reloc",  // RELOC
	".tls",    // TLS
	".debug",  // DEBUG
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
	//std::vector<BYTE> textSectionBinary_{};
	std::map<Section, std::vector<BYTE>> sectionHashs_{};

	//dll variable
	std::vector<std::tstring> dllList_{};

	//iat variable
	std::map <std::string, std::vector<std::string>> iatInfo_{}; //dll, functions
	std::set<std::tstring> EATInfo_{};

	//Utils
	std::vector<BYTE> ReadBinary();
	HANDLE CreateDummyProcess();
	void DestroyDummyProcess(HANDLE handle);

	//PROCESS INFO
	HANDLE GetProcessHandle() ;
	std::tstring GetProcessBinaryPath();

	//HASH
	std::vector<BYTE> CalcHash(PBYTE buffer,uint bufferSize);

	//SECTION
	std::vector<Section> GetSectionTypes(std::vector<BYTE>& binary);
	std::vector<BYTE> GetSectionData(HANDLE handle, const Section& sc);

	bool SectionCompare();

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

	void Test();

	
};

