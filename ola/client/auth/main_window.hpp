#pragma once

#include "solid/system/pimpl.hpp"
#include <QMainWindow>
#include <functional>
#include <string>
#include <vector>

namespace ola {
namespace client {
namespace auth {

using Uint8VectorT = std::vector<uint8_t>;
using CaptchaPointerT = QSharedPointer<std::vector<uint8_t>>;

class MainWindow : public QMainWindow {
    Q_OBJECT
    
public:
    using TryAuthenticateFunctionT = std::function<void(const std::string&, const std::string&, const std::string &)>;

    MainWindow(QWidget* parent = 0);
    ~MainWindow();

    void setUser(const std::string& _user);

    void start(TryAuthenticateFunctionT&& _fnc);

    void onCaptcha(std::vector<uint8_t>&& _captcha_image);

signals:
    void closeSignal();
    void onlineSignal(bool);
    void authFailSignal();
    void authSuccessSignal();

    void captchaSignal(CaptchaPointerT);
private slots:
    void onAuthClick();
    void onCreateClick();
    void onOnline(bool);
    void onAuthFail();
    void onAuthSuccess();

    void goAuthSlot(bool);
    void goCreateSlot(bool);
    void goBackSlot(bool);
    void goAboutSlot(bool);
    void captchaSlot(CaptchaPointerT);

    void authTextEdited(const QString& text);

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

Q_DECLARE_METATYPE(ola::client::auth::CaptchaPointerT);
