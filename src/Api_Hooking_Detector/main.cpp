#include "pch.h"  
#include "Api_Hooking_Detector.h"

using namespace std;

int main() {
	try {
		Detector detector(L"Project1.exe");

		detector.PrintIAT();
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