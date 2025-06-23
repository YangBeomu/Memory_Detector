#include "pch.h"  
#include "Memory_Detector.h"

using namespace std;

tstring g_fileName{};
tstring g_mode{}; // "monitor" or "console"
tstring g_tmpPathName(TEXT("Memory_Detector"));

const char* g_hash = "ec498c59eb6075b7632d925d41d7e135938f998520eff2aeb567a34328d92fcc";

void usage() {
	cout << "Usage:Api_Hooking_Detector.exe <process> <mode>" << endl;
	cout << "Example:Api_Hooking_Detector.exe Project1.exe monitor" << endl;
	cout << "This program detects API hooking by comparing DLLs and IAT." << endl;
	cout << "Available modes: monitor, console" << endl;
}

bool parse(int argc, TCHAR* argv[]) {
	if (argc < 3) {
		usage();
		return false;
	}
	if (argc > 3) {
		cerr << "[parse] Too many arguments." << endl;
		return false;
	}

	g_fileName = argv[1];
	g_mode = argv[2];

	return true;
}

void PrintList() {
	cout << "===== API Hooking Detector Commands =====" << endl;
	cout << "1. Print Hash" << endl;
	cout << "2. Compare Hash" << endl;
	cout << "3. Print DLL List" << endl;
	cout << "4. Compare DLL List" << endl;
	cout << "5. Print IAT Information" << endl;
	cout << "6. Compare IAT (Import Address Table)" << endl;
	cout << "7. Run Full Detection" << endl;
	cout << "8. Stop Full Detection" << endl;
	cout << "9. Run Test Function" << endl;
	cout << "10. Clear Screen" << endl;
	cout << "0. Exit" << endl;
	cout << "=========================================" << endl;
	cout << "Enter your choice: ";
}

int _tmain(int argc, TCHAR* argv[]) {
	try {
		if (!parse(argc, argv)) throw runtime_error("Failed to parse");

		std::vector<BYTE> hash(32, 0);
		core::HexFromString(hash.data(), hash.size(), g_hash);

		NetworkManager nm(NetworkManager::Type::CLIENT, ntohl(Ip("127.0.0.1")), 8987);
		nm.Run();

		std::tstring logPath = utils::GetTmpPathWithMkDir(g_tmpPathName);
		if (logPath.empty()) throw runtime_error("Failed to call GetTmpPath");


		Detector detector(g_fileName);
		
		Logger logger(logPath);

		if (g_mode.compare(_T("console")) == 0) {
			string input{};

			while (1) {
				PrintList();

				getline(cin, input);

				switch (stoi(input)) {
				case 0: // Exit
					cout << "Exiting program..." << endl;
					return EXIT_SUCCESS;
				case 1: // Print Hash (이전 2번)
				{
					cout << "===== Hash Information =====" << endl;
					detector.PrintHash();
					cout << "============================" << endl;
				}
				break;
				case 2: // Compare Hash (이전 1번)
				{
					cout << "===== Hash =====" << endl;

					if (!detector.CompareHash(hash)) {
						cout << "Hash Comparison result: Mismatch detected!" << endl;
						cout << "File might have been modified or tampered with." << endl;
					}

					cout << "================" << endl;
				}
				break;
				case 3: // Print DLL List
				{
					cout << "===== DLL List =====" << endl;
					detector.PrintDLLs();
					cout << "====================" << endl;
				}
				break;
				case 4: // Compare DLL List
				{
					cout << "===== Comparing DLL List =====" << endl;
					bool result = detector.CompareDLLs();
					cout << "DLL Comparison result: " << (result ? "No hooks detected" : "Hooks detected!") << endl;
					cout << "=============================" << endl;
				}
				break;
				case 5: // Print IAT Information
				{
					cout << "===== Import Address Table Information =====" << endl;
					detector.PrintIAT();
					cout << "==========================================" << endl;
				}
				break;
				case 6: // Compare IAT
				{
					cout << "===== Comparing IAT =====" << endl;
					bool result = detector.CompareIAT();
					cout << "IAT Comparison result: " << (result ? "No hooks detected" : "Hooks detected!") << endl;
					cout << "========================" << endl;
				}
				break;
				case 7: // Run Full Detection
				{
					cout << "===== Running Full Detection =====" << endl;
					detector.Run();
					logger.Log(detector, Logger::XML);
					cout << "=================================" << endl;
				}
				break;
				case 8: // Stop Detection
				{
					cout << "===== Stopping Detection =====" << endl;
					detector.Stop();
					cout << "==============================" << endl;
				}
				break;
				case 9: // Test Function
				{
					cout << "===== Running Test Function =====" << endl;
					if (detector.detect(hash)) {
						logger.Log(detector, Logger::XML);
						auto files = utils::GetTempFiles(g_tmpPathName);
						if (files.empty()) throw runtime_error("Failed to call GetTempFiles");

						for (const auto& file : files)
							nm.PushData(reinterpret_cast<const char*>(file.data()), file.size());


						utils::RemoveFIles(g_tmpPathName);

						return 0;
						break;
					}
					cout << "=================================" << endl;
				}
				break;
				case 10: // Clear Screen
					system("CLS");
					break;
				default:
					cout << "Invalid option. Please try again." << endl;
					break;
				}

				cout << endl;
			}
		}
		else if (g_mode.compare(_T("monitor")) == 0) {
			while (1) {
				std::this_thread::sleep_for(chrono::milliseconds(100));

				if (detector.detect(hash)) {
					logger.Log(detector, Logger::XML);
					auto fileBinarys = utils::GetTempFiles(g_tmpPathName);
					if (fileBinarys.empty()) throw runtime_error("Failed to call GetTempFiles");

					for (const auto& file : fileBinarys)
						nm.PushData(reinterpret_cast<const char*>(file.data()), file.size());

					utils::RemoveFIles(g_tmpPathName);

					return 0;
					break;
				}
			}
		}
	}
	catch (const std::exception& e) {
		cerr << "[main] Exception: " << e.what() << endl;
		return EXIT_FAILURE;
	}
	catch (...) {
		cerr << "[main] Unknown exception occurred." << endl;
		return EXIT_FAILURE;
	}
}