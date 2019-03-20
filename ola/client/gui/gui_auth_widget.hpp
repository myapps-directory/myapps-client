#pragma once

#include "solid/system/pimpl.hpp"
#include <QWidget>
#include <functional>
#include <string>

namespace ola {
namespace client {
namespace gui {

class AuthWidget : public QWidget {
    Q_OBJECT

public:
    using TryAuthenticateFunctionT = std::function<void(const std::string&, const std::string&)>;

    AuthWidget(QWidget* parent = 0);
    ~AuthWidget();

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

private:
    struct Data;
    solid::PimplT<Data> pimpl_;
};
} //namespace gui
} //namespace client
} //namespace ola
