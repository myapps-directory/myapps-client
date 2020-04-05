#pragma once

#include "solid/system/pimpl.hpp"
#include <QMainWindow>
#include <functional>
#include <string>
#include <vector>

namespace ola {
namespace client {
namespace auth {

struct AmendFetch {
    QString user_;
    QString email_;
};

using Uint8VectorT = std::vector<uint8_t>;
using CaptchaPointerT = QSharedPointer<Uint8VectorT>;
using AmendFetchPointerT = QSharedPointer<AmendFetch>;

struct Configuration {
    using AuthenticateFunctionT = std::function<bool(const std::string&, const std::string&, const std::string &)>;
    using CreateFunctionT = std::function<bool(const std::string&, const std::string &, const std::string &, const std::string &)>;
    using AmendFunctionT = std::function<bool(const std::string&, const std::string &, const std::string &, const std::string &)>;
    using ValidateFunctionT = std::function<bool(const std::string&)>;
    using ResendValidateFunctionT     = std::function<bool()>;
    using AuthFetchFunctionT = std::function<bool()>;
    using LogoutFunctionT = std::function<bool()>;

    QString                 login_;
    AuthenticateFunctionT authenticate_fnc_;
    CreateFunctionT       create_fnc_;
    AmendFunctionT        amend_fnc_;
    ValidateFunctionT     validate_fnc_;
    ResendValidateFunctionT resend_validate_fnc_;
    AuthFetchFunctionT      auth_fetch_fnc_;
    LogoutFunctionT         logout_fnc_;
};

class MainWindow : public QMainWindow {
    Q_OBJECT
    
public:
    

    MainWindow(QWidget* parent = 0);
    ~MainWindow();

    void setUser(const std::string& _user);

    void start(
        Configuration &&_config
    );

    void onCaptcha(std::vector<uint8_t>&& _captcha_image);
    void onAmendFetch(const std::string& _user, const std::string& _email);
    void onEmailValidationResent();
 
signals:
    void closeSignal();
    void onlineSignal(bool);
    void authSignal(bool);
    void authValidateSignal();

    void captchaSignal(CaptchaPointerT);
    void amendFetchSignal(AmendFetchPointerT);
    void emailValidationResentSignal();
private slots:
    void onAuthClick();
    void onLogoutClick();
    void onCreateClick();
    void onValidateClick();
    void onAmendClick();
    void onResetClick();
    void onValidateResendClick();

    void onOnline(bool);
    void onAuthSlot(bool);
    void onAuthValidate();

    void goAuthSlot(bool);
    void goAmendSlot(bool);
    void goCreateSlot(bool);
    void goBackSlot(bool);
    void goAboutSlot(bool);
    void captchaSlot(CaptchaPointerT);
    void amendFetchSlot(AmendFetchPointerT);

    void authTextEdited(const QString& text);
    void createTextEdited(const QString& text);
    void validateTextEdited(const QString& text);
    void amendTextEdited(const QString& text);
    void emailValidationResentSlot();
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
Q_DECLARE_METATYPE(ola::client::auth::AmendFetchPointerT);
