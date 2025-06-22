#include "pch.h"  
#include "Logger.h"  

using namespace std;
using namespace core;

Logger::Logger(tstring path)
	:filePath_(path) {
};

//logging
void Logger::WarningMsg(const string& msg) {
	cerr << "[Logger]" << msg << endl;
}

void Logger::ErrorMsg(const string& msg) {
	cerr << "[Logger]" << msg << endl;
	exit(1);
}


uint64_t Logger::GetTimeStamp() {
	auto now = chrono::system_clock::now();
	uint64_t ret = chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

	return ret;
}

std::vector<BYTE> Logger::GetNetworkInformation() {
	vector<BYTE> buffer(BUFSIZ);

	try {
		FILE* fp = _popen("ipconfig/all", "r");
		if (fp == nullptr) throw runtime_error("Failed to get file pointer");
		int readed{};

		do {
			if (readed == buffer.size()) buffer.resize(buffer.size() * 2);
		} while ((readed = fread(buffer.data(), 1, buffer.size(), fp)));
	}
	catch (const exception& e) {
		WarningMsg(string("<GetNetworkInformation> ").append(e.what()));
	}

	return buffer;
}

tstring Logger::GenerateFileName() {
	tstring ret{};

	try {
		auto cpName = core::GetComputerName();
		if (cpName.empty()) throw runtime_error("Failed to get computer name.");

		ret.append(cpName);

		ret.append(TEXT("_"));

		uint64_t timeStamp = GetTimeStamp();
		if (!timeStamp) throw runtime_error("Failed to get time stamp.");

#if _UNICODE
		ret.append(to_wstring(timeStamp));
#else
		ret.append(to_string(timeStamp));
#endif
	}
	catch (const exception& e) {
		WarningMsg(string("<GenerateFileName> ").append(e.what()));
	}

	return ret;
}

void Logger::OnSync(IFormatter& formatter) {
	for (auto& logMsg : logMsgs_) {
		for (tstring& value : logMsg.second) {
			formatter
				+ core::sPair(logMsg.first.c_str(), value);
		}
	}
}

void Logger::Logging(std::tstring& key, std::tstring& value) {
	logMsgs_[key].push_back(value);
}

bool Logger::Save(const Logger::LogType& type) {
	bool ret{};

	auto fileName = GenerateFileName();

	switch (type) {
	case LogType::BINARY:
		ret = core::WriteBinToFile(this, (filePath_ + fileName).c_str());
		break;
	case LogType::JSON:
		ret = core::WriteJsonToFile(this, (filePath_ + fileName).c_str());
		break;
	case LogType::XML:
		ret = core::WriteXmlToFile(this, (filePath_ + fileName).c_str());
		break;
	default:
		break;
	}

	if (!ret) return false;

	logMsgs_.clear();

	return true;
}

void Logger::Log(Detector& dt, Logger::LogType type) {
	try {
		auto log = dt.GetLog();
		if (log.isEmpty()) throw runtime_error("Failed to get log list");
		auto ni = GetNetworkInformation();
		if (ni.empty()) throw runtime_error("Failed to get network information");

		//network information
		{
			std::tstring key = _T("NetworkInformation");
			std::tstring value;
			if (!ni.empty()) {
#if _UNICODE
				value.append(core::WCSFromMBS(string(ni.begin(), ni.end())));
				//value.append(wstring(ni.begin(), ni.end()));
#else
				value.append(string(ni.begin(), ni.end()));
#endif
			}
			Logging(key, value);
		}

		// 기본 프로세스 정보 로깅
		std::tstring key = _T("ProcessName");
		std::tstring value = log.processName_;
		Logging(key, value);

		// 타임스탬프 로깅
		key = _T("StartTimestamp");
#if _UNICODE
		value = std::to_wstring(log.startTimestamp_);
#else
		value = std::to_string(log.startTimestamp_);
#endif
		Logging(key, value);

		key = _T("CurrentTimestamp");
#if _UNICODE
		value = std::to_wstring(log.currentTimestamp_);
#else
		value = std::to_string(log.currentTimestamp_);
#endif
		Logging(key, value);

		// 프로세스 경로 및 ID 로깅
		key = _T("ProcessBinaryPath");
		value = log.processBinaryPath_;
		Logging(key, value);

		key = _T("ProcessRunning");
#if _UNICODE
		value = log.processRunning ? L"True" : L"False";
#else
		value = log.processRunning ? "True" : "False";
#endif
		Logging(key, value);

		// 바이너리 해시 로깅
		key = _T("ProcessBinaryHash");
		if (!log.processBinaryHash_.empty()) {
			std::tstring hashStr;
#if _UNICODE
			for (const auto& byte : log.processBinaryHash_) {
				TCHAR hex[3];
				_stprintf_s(hex, _T("%02X"), byte);
				hashStr += hex;
			}
#else
			for (const auto& byte : log.processBinaryHash_) {
				char hex[3];
				sprintf_s(hex, "%02X", byte);
				hashStr += hex;
			}
#endif
			value = hashStr;
			Logging(key, value);
		}

		// 섹션 해시 로깅 
		{
			key = _T("SectionHashes");
			tstring ret{};

			for (const auto& section : log.sectionHashs_) {
#if _UNICODE
				std::tstring sectionInfo = L"Section: " + std::to_wstring(static_cast<int>(section.first)) + L" Hash: ";
				for (const auto& byte : section.second) {
					TCHAR hex[3];
					_stprintf_s(hex, _T("%02X"), byte);
					sectionInfo += hex;
				}
#else
				std::tstring sectionInfo = "Section: " + std::to_string(static_cast<int>(section.first)) + " Hash: ";
				for (const auto& byte : section.second) {
					char hex[3];
					sprintf_s(hex, "%02X", byte);
					sectionInfo += hex;
				}
#endif
				ret.append(sectionInfo.c_str());
			}
			Logging(key, ret);
		}

		// 프로세스 섹션 해시 로깅
		key = _T("ProcessSectionHashes");
		for (const auto& section : log.processSectionHashs_) {
#if _UNICODE
			std::tstring sectionInfo = L"Section: " + std::to_wstring(static_cast<int>(section.first)) + L" Hash: ";
			for (const auto& byte : section.second) {
				TCHAR hex[3];
				_stprintf_s(hex, _T("%02X"), byte);
				sectionInfo += hex;
			}
#else
			std::tstring sectionInfo = "Section: " + std::to_string(static_cast<int>(section.first)) + " Hash: ";
			for (const auto& byte : section.second) {
				char hex[3];
				sprintf_s(hex, "%02X", byte);
				sectionInfo += hex;
			}
#endif
			Logging(key, sectionInfo);
		}

		// DLL 목록 로깅
		{
			key = _T("DllList");
			tstring ret{};

#if _UNICODE
			for (const auto& dll : log.dllList_) {
				ret.append(dll.c_str());
			}
#else
			for (const auto& dll : log.dllList_) {
				ret.append(dll.c_str());
			}
#endif
			Logging(key, ret);
		}

		// 프로세스 DLL 목록 로깅
		{
			key = _T("ProcessDllList");
			tstring ret{};

#if _UNICODE
			for (const auto& dll : log.processDllList_) {
				ret.append(dll.c_str());
			}
#else
			for (const auto& dll : log.processDllList_) {
				ret.append(dll.c_str());
			}
#endif
			Logging(key, ret);
		}

		// IAT 정보 로깅 
		{
			key = _T("IATInfo");

			std::tstring ret{};
			for (const auto& iat : log.iatInfo_) {
				std::string dllName = iat.first;
#if _UNICODE
				std::tstring iatEntry = L"DLL: " + std::tstring(dllName.begin(), dllName.end()) + L" Functions: ";
				for (const auto& func : iat.second) {
					iatEntry += std::tstring(func.begin(), func.end()) + L", ";
				}
				if (!iat.second.empty()) {
					iatEntry.erase(iatEntry.length() - 2); // 마지막 ", " 제거
				}
#else
				std::tstring iatEntry = "DLL: " + std::tstring(dllName.begin(), dllName.end()) + " Functions: ";
				for (const auto& func : iat.second) {
					iatEntry += std::tstring(func.begin(), func.end()) + ", ";
				}
				if (!iat.second.empty()) {
					iatEntry.erase(iatEntry.length() - 2); // 마지막 ", " 제거
				}
#endif
				ret.append(iatEntry);
			}

			Logging(key, ret);
		}

		// 프로세스 IAT 정보 로깅
		{
			key = _T("ProcessIATInfo");

			tstring ret{};
			for (const auto& iat : log.processIatInfo_) {
				std::string dllName = iat.first;
#if _UNICODE
				std::tstring iatEntry = L"DLL: " + std::tstring(dllName.begin(), dllName.end()) + L" Functions: ";
				for (const auto& func : iat.second) {
					iatEntry += std::tstring(func.begin(), func.end()) + L", ";
				}
				if (!iat.second.empty()) {
					iatEntry.erase(iatEntry.length() - 2); // 마지막 ", " 제거
				}
#else
				std::tstring iatEntry = "DLL: " + std::tstring(dllName.begin(), dllName.end()) + " Functions: ";
				for (const auto& func : iat.second) {
					iatEntry += std::tstring(func.begin(), func.end()) + ", ";
				}
				if (!iat.second.empty()) {
					iatEntry.erase(iatEntry.length() - 2); // 마지막 ", " 제거
				}
#endif
				ret.append(iatEntry);
			}
			Logging(key, ret);
		}

		if (!Save(type)) throw runtime_error("Failed to save logger.");
	}
	catch (const exception& e) {
		WarningMsg(string("<Log> ").append(e.what()));
	}
}