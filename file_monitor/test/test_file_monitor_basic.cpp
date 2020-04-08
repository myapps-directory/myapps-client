#include "file_monitor/file_monitor.hpp"
#include <boost/filesystem.hpp>
#include <iostream>
#include <thread>
#include <fstream>

using namespace std;
namespace fs = boost::filesystem;
namespace {
void change_file(const fs::path& _path) {
    ofstream ofs(_path.generic_string());

    ofs << _path << endl;
    ofs.close();
}
}
int test_file_monitor_basic(int argc, char* argv[])
{
    file_monitor::Engine fm_engine;

    boost::system::error_code err;
    fs::remove_all("test", err);

    fs::create_directory("test", err);

    fm_engine.start();
    
    fm_engine.add("test/t1.txt", [](const fs::path& _dir, const fs::path& _name) {
        cout << "Modified: " << _dir << "/" << _name << endl;
    });
    this_thread::sleep_for(chrono::seconds(1));
    fm_engine.add("test/t2.txt", [](const fs::path& _dir, const fs::path& _name) {
        cout << "Modified: " << _dir << "/" << _name << endl;
    });
    this_thread::sleep_for(chrono::seconds(1));
    fm_engine.add("test/t3.txt", [](const fs::path& _dir, const fs::path& _name) {
        cout << "Modified: " << _dir << "/" << _name << endl;
    });

    this_thread::sleep_for(chrono::seconds(2));
    cout << "change t1" << endl;
    change_file("test/t1.txt");
    this_thread::sleep_for(chrono::seconds(1));
    cout << "change t2" << endl;
    change_file("test/t2.txt");
    this_thread::sleep_for(chrono::seconds(1));
    cout << "change t3" << endl;
    change_file("test/t3.txt");
    
    return 0;
}