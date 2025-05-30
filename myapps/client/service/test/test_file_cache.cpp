#include "../file_cache.hpp"
#include "solid/system/common.hpp"
#include "solid/system/log.hpp"
#include <iostream>
#include <sstream>
#include <vector>

using namespace std;
using namespace myapps::client::service::file_cache;
namespace {

struct FileStub : FileData {
};

} //namespace

int test_file_cache(int argc, char* argv[])
{

    solid::log_start(std::cout, {".*:VIEW"});

    fs::remove_all(".\\TEST");

    Engine engine;
    {
        Configuration config;

        config.base_path_ = ".\\TEST";
        config.max_size_  = 10 * 1024 * 1024;

        engine.start(std::move(config));
    }
    auto file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 1 * 1024 * 1024, "first application", "first build", "bin/1.test");
    const string some_data = "some data";
    file_ptr->writeToCache(100, some_data.data(), some_data.size());
    engine.close(*file_ptr);
    file_ptr.reset();

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 2 * 1024 * 1024, "first application", "first build", "bin/2.test");
    file_ptr->writeToCache(100, some_data.data(), some_data.size());
    engine.close(*file_ptr);
    file_ptr.reset();

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 3 * 1024 * 1024, "first application", "first build", "bin/3.test");
    file_ptr->writeToCache(100, some_data.data(), some_data.size());
    engine.close(*file_ptr);
    file_ptr.reset();

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 4 * 1024 * 1024, "first application", "first build", "bin/4.test");
    file_ptr->writeToCache(100, some_data.data(), some_data.size());
    engine.close(*file_ptr);
    file_ptr.reset();

    solid_check(engine.usedSize() == 10 * 1024 * 1024);

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 1 * 1024 * 1024, "first application", "first build", "bin/1.test");
    solid_check(file_ptr->file_.rangeCount() == 1);
    engine.close(*file_ptr);
    file_ptr.reset();

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 2 * 1024 * 1024, "first application", "first build", "bin/2.test");
    solid_check(file_ptr->file_.rangeCount() == 1);
    engine.close(*file_ptr);
    file_ptr.reset();

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 3 * 1024 * 1024, "first application", "first build", "bin/3.test");
    solid_check(file_ptr->file_.rangeCount() == 1);
    engine.close(*file_ptr);
    file_ptr.reset();

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 4 * 1024 * 1024, "first application", "first build", "bin/4.test");
    solid_check(file_ptr->file_.rangeCount() == 1);
    engine.close(*file_ptr);
    file_ptr.reset();

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 5 * 1024 * 1024, "first application", "first build", "bin/5.test");
    file_ptr->writeToCache(100, some_data.data(), some_data.size());
    engine.close(*file_ptr);
    file_ptr.reset();

    solid_check(engine.usedSize() == 9 * 1024 * 1024);

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 4 * 1024 * 1024, "first application", "first build", "bin/4.test");
    solid_check(file_ptr->file_.rangeCount() == 1);
    engine.close(*file_ptr);
    file_ptr.reset();

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 1 * 1024 * 1024, "first application", "first build", "bin/1.test");
    solid_check(file_ptr->file_.rangeCount() == 0);
    engine.close(*file_ptr);
    file_ptr.reset();

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 4 * 1024 * 1024, "first application", "first build", "bin/4.test");
    solid_check(file_ptr->file_.rangeCount() == 1);
    engine.close(*file_ptr);
    file_ptr.reset();

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 5 * 1024 * 1024, "first application", "first build", "bin/5.test");
    solid_check(file_ptr->file_.rangeCount() == 1);
    engine.close(*file_ptr);
    file_ptr.reset();

    solid_check(engine.usedSize() == 10 * 1024 * 1024);
    solid_check(engine.fileCount() == 3);

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 2 * 1024 * 1024, "first application", "first build", "bin/2.test");
    solid_check(file_ptr->file_.rangeCount() == 0);
    engine.close(*file_ptr);
    file_ptr.reset();

    solid_check(engine.usedSize() == 7 * 1024 * 1024);
    solid_check(engine.fileCount() == 2);

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 3 * 1024 * 1024, "first application", "first build", "bin/4.test");
    solid_check(file_ptr->file_.rangeCount() == 0);
    engine.close(*file_ptr);
    file_ptr.reset();

    solid_check(engine.usedSize() == 10 * 1024 * 1024);
    solid_check(engine.fileCount() == 3);

    file_ptr = make_unique<FileStub>();
    engine.open(*file_ptr, 5 * 1024 * 1024, "first application", "first build", "bin/5.test");
    solid_check(file_ptr->file_.rangeCount() == 1);
    engine.close(*file_ptr);
    file_ptr.reset();

    solid_check(engine.applicationCount() == 1);
    auto check_app_lambda = [](const std::string& _app_name, const std::string& _build_unique) {
        if (_app_name == "first application" && _build_unique == "first build") {
            return false;
        }
        return true;
    };
    engine.removeOldApplications(check_app_lambda);
    solid_check(engine.applicationCount() == 0);

    fs::remove_all(".\\TEST");
    size_t   app_count  = 0;
    size_t   file_count = 0;
    uint64_t total_size = 0;
    {
        Engine engine;
        {
            Configuration config;

            config.base_path_ = ".\\TEST";
            config.max_size_  = 10 * 1024 * 1024;

            engine.start(std::move(config));
        }

        auto file_ptr = make_unique<FileStub>();
        engine.open(*file_ptr, 1 * 1024 * 1024, "first application", "first build", "bin/1.test");
        file_ptr->writeToCache(100, some_data.data(), some_data.size());
        engine.close(*file_ptr);
        file_ptr.reset();

        file_ptr = make_unique<FileStub>();
        engine.open(*file_ptr, 2 * 1024 * 1024, "first application", "first build", "bin/2.test");
        file_ptr->writeToCache(100, some_data.data(), some_data.size());
        engine.close(*file_ptr);
        file_ptr.reset();

        file_ptr = make_unique<FileStub>();
        engine.open(*file_ptr, 3 * 1024 * 1024, "second application", "first build", "bin/1.test");
        file_ptr->writeToCache(100, some_data.data(), some_data.size());
        engine.close(*file_ptr);
        file_ptr.reset();

        app_count  = engine.applicationCount();
        file_count = engine.fileCount();
        total_size = engine.usedSize();
    }
    {
        Engine engine;
        {
            Configuration config;

            config.base_path_ = ".\\TEST";
            config.max_size_  = 10 * 1024 * 1024;

            engine.start(std::move(config));
        }
        solid_check(app_count == engine.applicationCount());
        solid_check(file_count == engine.fileCount());
        solid_check(total_size == engine.usedSize());
    }

    return 0;
}