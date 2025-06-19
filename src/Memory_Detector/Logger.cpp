#include "pch.h"  
#include "Logger.h"  

using namespace std;  
using namespace core;  

Logger::Logger(tstring path)  
	:filePath_(path) {
};
	
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

void Logger::Save(const Logger::LogType& type) {
	switch (type) {
		case LogType::BINARY:  
			core::WriteBinToFile(this, filePath_.c_str());
			break;
		case LogType::JSON:
			core::WriteJsonToFile(this, filePath_.c_str());
			break;
		case LogType::XML:
			core::WriteXmlToFile(this, filePath_.c_str());
			break;
		default:
			break;
	}
}