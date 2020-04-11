#include "file_monitor/file_monitor.hpp"
#include "solid/system/cassert.hpp"
#include "solid/system/exception.hpp"
#include "solid/system/log.hpp"

#include <thread>
#include <deque>
#include <atomic>
#include <mutex>
#include <vector>
#include <windows.h>

using namespace solid;
using namespace std;

namespace fs = boost::filesystem;

namespace file_monitor{

namespace{
solid::LoggerT logger("file_monitor");

    using AddItemPairT = std::pair<fs::path, Engine::OnChangeFunctionT>;
    using AddItemDequeT = std::deque<AddItemPairT>;

}

struct Engine::Implementation{
    mutex        mtx_;
    thread       thr_;
    atomic<bool> running_ = false;
    AddItemDequeT prod_dq_;
    HANDLE        notification_handle_ = nullptr;

    void threadRun();

    void notify() {
        SetEvent(notification_handle_);
    }
};

Engine::Engine():pimpl_(make_pimpl<Implementation>()){}

Engine::~Engine(){
    stop();
}

void Engine::start(){
    bool expect = false;
    if(pimpl_->running_.compare_exchange_strong(expect, true)){
        pimpl_->notification_handle_ = CreateEvent(
            NULL, // default security attributes
            FALSE, // manual-reset event
            FALSE, // initial state is nonsignaled
            TEXT("NotifyEvent") // object name
        ); 

        pimpl_->thr_ = thread([this](){pimpl_->threadRun();});
    }
}

void Engine::stop(){
    bool expect = true;
    if(pimpl_->running_.compare_exchange_strong(expect, false)){
        solid_assert(pimpl_->thr_.joinable());
        pimpl_->notify();
        pimpl_->thr_.join();
    }
}

void Engine::add(const boost::filesystem::path &_file_path, OnChangeFunctionT &&_fnc){
    lock_guard<mutex> lock(pimpl_->mtx_);
    pimpl_->prod_dq_.emplace_back(_file_path, std::move(_fnc));
    if (pimpl_->prod_dq_.size() == 1) {
        pimpl_->notify();
    }
}
namespace {
struct ItemStub {
    fs::path name_;
    Engine::OnChangeFunctionT fnc_;
    chrono::system_clock::time_point write_time_point_;
};

struct DirectoryStub {
    fs::path path_;
    vector<ItemStub> item_vec_;
};
struct Context {
    vector<HANDLE> handle_vec_;
    AddItemDequeT  cons_dq_;
    deque<DirectoryStub> dir_dq_;

    DirectoryStub& directory(const size_t _idx)
    {
        return dir_dq_[_idx];
    }

    const DirectoryStub& directory(const size_t _idx) const
    {
        return dir_dq_[_idx];
    }

    const fs::path& directoryPath(const size_t _idx) {
        return directory(_idx).path_;
    }

    size_t add(AddItemPairT& _ritem, bool& _ris_new_dir) {
        auto abs_path = fs::absolute(_ritem.first);
        auto dir_path = abs_path.parent_path();
        auto name     = abs_path.leaf();

        size_t i = 0;
        for (; i < dir_dq_.size(); ++i) {
            const auto& dir = dir_dq_[i];
            if (dir.path_ == dir_path) {
                break;
            }
        }

        if (i == dir_dq_.size()) {
            dir_dq_.emplace_back();
            dir_dq_.back().path_ = std::move(dir_path);
            _ris_new_dir         = true;
        } else {
            _ris_new_dir = false;
        }
        
        auto& dir = dir_dq_[i];

        dir.item_vec_.emplace_back();
        dir.item_vec_.back().fnc_  = std::move(_ritem.second);
        dir.item_vec_.back().name_ = std::move(name);
        return i;
    }
};
}

void Engine::Implementation::threadRun()
{
    Context ctx;
    ctx.handle_vec_.emplace_back(notification_handle_);
    {
        lock_guard<mutex> lock(mtx_);
        swap(prod_dq_, ctx.cons_dq_);
    }
    for (auto& item : ctx.cons_dq_) {
        bool         new_dir  = false;
        const size_t dir_idx = ctx.add(item, new_dir);
        const auto&  dir_path = ctx.directoryPath(dir_idx);
        if (new_dir) {
            ctx.handle_vec_.emplace_back(
                FindFirstChangeNotification(
                    dir_path.string().c_str(), // directory to watch
                    TRUE, // watch the subtree
                    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_LAST_WRITE) // watch dir name changes
            );
        }

        ItemStub& ritem = ctx.directory(dir_idx).item_vec_.back();
        boost::system::error_code err;
        ritem.write_time_point_ = chrono::system_clock::from_time_t(fs::last_write_time(dir_path / ritem.name_, err));
        ritem.fnc_(dir_path, ritem.name_, ritem.write_time_point_);
    }

    ctx.cons_dq_.clear();

    while (running_) {
        const auto waitrv = WaitForMultipleObjects(ctx.handle_vec_.size(), ctx.handle_vec_.data(), FALSE, INFINITE);

        if (waitrv == WAIT_OBJECT_0) {
            //notification
            {
                lock_guard<mutex> lock(mtx_);
                swap(prod_dq_, ctx.cons_dq_);
            }
            for (auto& item : ctx.cons_dq_) {
                bool         new_dir  = false;
                const size_t dir_idx  = ctx.add(item, new_dir);
                const auto&  dir_path = ctx.directoryPath(dir_idx);
                if (new_dir) {
                    ctx.handle_vec_.emplace_back(
                        FindFirstChangeNotification(
                            dir_path.string().c_str(), // directory to watch
                            TRUE, // watch the subtree
                            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_LAST_WRITE) // watch dir name changes
                    );
                }

                ItemStub& ritem         = ctx.directory(dir_idx).item_vec_.back();
                boost::system::error_code err;
                ritem.write_time_point_ = chrono::system_clock::from_time_t(fs::last_write_time(dir_path / ritem.name_, err));
                ritem.fnc_(dir_path, ritem.name_, ritem.write_time_point_);
            }
        } else if (waitrv > WAIT_OBJECT_0 && waitrv < (WAIT_OBJECT_0 + ctx.handle_vec_.size())) {
            const size_t handle_idx = waitrv - WAIT_OBJECT_0;
            const size_t dir_idx = waitrv - WAIT_OBJECT_0 - 1;
            auto&        dir     = ctx.directory(dir_idx);
            for (auto& item : dir.item_vec_) {
                boost::system::error_code err;
                const auto new_time = chrono::system_clock::from_time_t(fs::last_write_time(dir.path_ / item.name_, err));
                if (new_time != item.write_time_point_) {
                    item.write_time_point_ = new_time;
                    item.fnc_(dir.path_, item.name_, item.write_time_point_);
                }
            }
            FindNextChangeNotification(ctx.handle_vec_[handle_idx]);
        } else {
            solid_check_log(false, logger, "WaitForMultipleObjects returned error. A Monitored Directory might not exist!");
        }
    }

    for (auto h : ctx.handle_vec_) {
        CloseHandle(h);
    }
}

}//namespace file_monitor