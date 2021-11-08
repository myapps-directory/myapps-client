#include "../file_cache.hpp"
#include "solid/system/common.hpp"
#include <iostream>

using namespace std;
using namespace myapps::client::service::file_cache;

void test_namefy(const std::string& _path)
{
    cout << namefy(_path) << '\t' << denamefy(namefy(_path)) << endl;
    assert(_path == denamefy(namefy(_path)));
}

int test_file_namefy(int argc, char* argv[])
{
    test_namefy("\\_&_&&__&&&");
    test_namefy("&\\&\\&&\\&&&");
    test_namefy("\\&\\&\\&&\\&&&\\");
    test_namefy("\\&_\\&_\\&&_\\&&&_\\");
    test_namefy("_&_\\&_\\&_");

    return 0;
}