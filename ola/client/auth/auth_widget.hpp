#pragma once

#include "solid/system/pimpl.hpp"
#include <QWidget>
#include <functional>
#include <string>

namespace ola {
namespace client {
namespace auth {

class Widget : public QWidget {
    Q_OBJECT

public:
    using TryAuthenticateFunctionT = std::function<void(const std::string&, const std::string&)>;

    Widget(QWidget* parent = 0);
    ~Widget();

    void setUser(const std::string& _user);

    void start(TryAuthenticateFunctionT&& _fnc);
signals:
    void closeSignal();
    void offlineSignal(bool);
    void authFailSignal();
    void authSuccessSignal();
private slots:
    void onAuthClick();
    void onOffline(bool);
    void onAuthFail();
    void onAuthSuccess();

private:
    void closeEvent(QCloseEvent*) override;
    bool eventFilter(QObject* obj, QEvent* event) override;

private:
    struct Data;
    solid::PimplT<Data> pimpl_;
};
} //namespace auth
} //namespace client
} //namespace ola
