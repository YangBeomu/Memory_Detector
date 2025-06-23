#include "pch.h"
#include "Memory_Detector_Server.h"

using namespace std;

Ip g_ip{};
uint16_t g_port{};
tstring g_logPath(TEXT("Memory_Detecor_Server"));

void usage() {
    std::cout << "Memory Detector Server" << std::endl;
    std::cout << "Usage: " << std::endl;
    std::cout << "  memory_detector_server <port>" << std::endl;
    std::cout << "Examples: " << std::endl;
    std::cout << "  memory_detector_server 8080" << std::endl;
}

bool parse(int argc, char* argv[]) {
	if (argc < 2) {
		usage();
		return false;
	}

	g_port = stoi(argv[1]);

	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(argc, argv)) return -1;

	std::tstring logPath{};

	try {
		NetworkManager nm(NetworkManager::Type::SERVER, htonl(g_ip), g_port);

		nm.Run();

		while (1) {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));

			if (nm.DataSize()) {
				auto data = nm.PopData();

				if (data.isEmpty()) throw runtime_error("Data is empty.");

				auto timestamp = utils::GetTimeStamp();

				tstring title{};

#if _UNICODE
				title = to_wstring(timestamp);
#else
				title = to_string(timestamp);
#endif

				if (!utils::SaveFile(g_logPath, title.c_str(), data.buffer_))
					throw runtime_error("Failed to call SaveFile");
			}
		}
	}
	catch (const exception& e) {
		cerr << "[main] " << e.what() << endl;
	}
}