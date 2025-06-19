#pragma once
class Logger : public core::IFormatterObject
{
private:
	std::tstring fileTitle_{};
	std::tstring filePath_{};
	std::map<std::tstring, std::vector<std::tstring>> logMsgs_{};

protected:

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
	void Logging(std::tstring& key, std::tstring& value);
	void Save(const LogType& type);
};

