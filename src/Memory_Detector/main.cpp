#include "pch.h"  
#include "Memory_Detector.h"

using namespace std;

tstring g_fileName{};
tstring g_logPath{};

void usage() {
	cout << "Usage:Api_Hooking_Detector.exe <process> <log_path>" << endl;
	cout << "Example:Api_Hooking_Detector.exe Project1.exe ." << endl;
	cout << "This program detects API hooking by comparing DLLs and IAT." << endl;
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
	g_logPath = argv[2];

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

		Detector detector(g_fileName);
		Logger logger(g_logPath);

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
					BYTE tmp[] = "test";
				
					vector<BYTE> test{sizeof(tmp)};
					memcpy(test.data(), tmp, test.size());

					if (!detector.CompareHash(test)) {
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
					detector.Run();;
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
					detector.Test();
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
	catch (const std::exception& e) {
		cerr << "[main] Exception: " << e.what() << endl;
		return EXIT_FAILURE;
	}
	catch (...) {
		cerr << "[main] Unknown exception occurred." << endl;
		return EXIT_FAILURE;
	}
}