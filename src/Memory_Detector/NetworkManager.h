#pragma once

//#include <iostream>
//#include <thread>
//#include <mutex>
//#include <condition_variable>
//
//#include <vector>
//#include <list>
//
//#include <cstdint>
//#include <uchar.h>
//
//#if _WIN64 
//#include <Windows.h>
//#endif
//
//#include "ip.h"

class NetworkManager {
public:
	enum Type {
		SERVER,
		CLIENT
	};

protected:
	enum status {
		STATUS_IDLE = 0,
		STATUS_RUNNING = 1,
		STATUS_STOPPED = 2,
		STATUS_ENDED = 3,
		STATUS_ERROR = 4,
		STATUS_MAX = 5
	};

	enum {
		RESET = -1,
		FINISH,
	};

private:
	struct NetworkInformation {
		SOCKET socket_{};
		sockaddr_in sockAddr_{};
	};

	template<typename T>
	struct DataType {
		uint32_t len_{};
		std::vector<T> buffer_{};

		bool isEmpty() const { if (memcmp(this, DataType(), sizeof(DataType)) == 0) return true; return false; }
		
	};

#if _WIN64
		WSADATA wsaData_ {};
#endif

	Ip ip_{};
	uint16_t port_{};
	NetworkInformation ni_{};
	std::vector<NetworkInformation> cni_{};

	std::list<DataType<char>> dataList_{};

	//control
	Type type_{};
	status status_{ STATUS_IDLE };

	//Logging
	void WarningMsg(const std::string& msg);
	void ErrorMsg(const std::string& msg);

	//control
	bool Init();

	void Play();
	void Pause();
	void End();

protected:
	//thread
	std::thread workerThread_{};
	std::mutex dataMtx_{}, statusMtx_{};
	std::condition_variable cv_{};

	//comm
	void NetworkManagerWorker();
	int ClientCommWork(DataType<char>& data);
	void ServerCommWorker(SOCKET socket);

public:
	static constexpr int BUFFER_SIZE = 1024;

	explicit NetworkManager(const Type type, const Ip& ip, const uint16_t port);
	~NetworkManager();

	//data
	int DataSize();
	void PushData(const char* buffer, const uint32_t len);
	DataType<char> PopData();

	//control
	void Run();
	void Stop();
};

