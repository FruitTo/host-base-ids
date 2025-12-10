#include <iostream>
#include <string>
#include <regex>
#include <vector>

using namespace std;

int main() {
    // จำลองข้อมูลจาก Log ที่คุณส่งมา
    vector<string> log_lines = {
        "Sun Dec  7 02:13:32 2025 [pid 3981] [fruitto] FAIL LOGIN: Client \"::ffff:192.168.122.1\"",
        "Sun Dec  7 02:13:35 2025 [pid 3984] [fruitto] FAIL LOGIN: Client \"::ffff:192.168.122.1\"",
        "Sun Dec  7 02:13:39 2025 [pid 3986] [fruitto] FAIL LOGIN: Client \"::ffff:192.168.122.1\""
    };

    // Regex ที่ปรับปรุงแล้ว (รองรับทั้ง ::ffff: และไม่มี)
    // ใช้ R"ftp(...)ftp" เพื่อความชัวร์เรื่องเครื่องหมาย "
    regex pattern(R"ftp(FAIL LOGIN: Client "(?:::ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")ftp");
    smatch matches;

    cout << "--- Testing Log Parsing ---" << endl;

    for (const auto& line : log_lines) {
        if (regex_search(line, matches, pattern)) {
            // matches[1] คือกลุ่มตัวเลข IP ที่เรา Capture ไว้
            string ip = matches[1];
            cout << "[MATCH] Extracted IP: " << ip << endl;
        } else {
            cout << "[FAIL] No match found for line." << endl;
        }
    }

    return 0;
}