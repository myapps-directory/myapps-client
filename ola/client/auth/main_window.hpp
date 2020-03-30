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
    using AuthenticateFunctionT = std::function<void(const std::string&, const std::string&, const std::string &)>;
    using CreateFunctionT = std::function<void(const std::string&, const std::string &, const std::string &, const std::string &)>;
    using AmendFunctionT = std::function<void(const std::string&, const std::string &, const std::string &, const std::string &)>;
    using ValidateFunctionT = std::function<void(const std::string&)>;

    MainWindow(QWidget* parent = 0);
    ~MainWindow();

    void setUser(const std::string& _user);

    void start(
        const QString &_auth_user,
        AuthenticateFunctionT&& _auth_fnc,
        CreateFunctionT &&_create_fnc,
        AmendFunctionT &&_amend_fnc,
        ValidateFunctionT &&_validate_fnc
    );

    void onCaptcha(std::vector<uint8_t>&& _captcha_image);

signals:
    void closeSignal();
    void onlineSignal(bool);
    void authFailSignal();
    void authSuccessSignal();
    void authValidateSignal();

    void captchaSignal(CaptchaPointerT);
private slots:
    void onAuthClick();
    void onCreateClick();
    void onValidateClick();

    void onOnline(bool);
    void onAuthFail();
    void onAuthSuccess();
    void onAuthValidate();

    void goAuthSlot(bool);
    void goAmendSlot(bool);
    void goCreateSlot(bool);
    void goBackSlot(bool);
    void goAboutSlot(bool);
    void captchaSlot(CaptchaPointerT);

    void authTextEdited(const QString& text);
    void createTextEdited(const QString& text);
    void validateTextEdited(const QString& text);

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
