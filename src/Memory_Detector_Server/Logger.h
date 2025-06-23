#pragma once

#include "Detector.h"

class Logger : public core::IFormatterObject
{
private:
	std::tstring filePath_{};
	std::map<std::tstring, std::vector<std::tstring>> logMsgs_{};

	//logging msg
	void WarningMsg(const std::string& msg);
	void ErrorMsg(const std::string& msg);

	//utils
	uint64_t GetTimeStamp();
	std::vector<BYTE> GetNetworkInformation();
	std::tstring GenerateFileName();


protected:
	void Logging(std::tstring& key, std::tstring& value);
	

public:
	enum LogType {
		BINARY = 0,
		JSON = 1,
		XML = 2,
	};

	explicit Logger(std::tstring path);
	virtual ~Logger() = default;

	std::tstring GetPath() const { return filePath_; };
	void SetPath(std::tstring path) { filePath_ = path; };

	void OnSync(core::IFormatter& formatter);
	
	bool Save(const LogType& type);
	
	void Log(Detector& dt, Logger::LogType type);
};

