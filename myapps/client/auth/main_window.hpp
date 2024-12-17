#pragma once

#include "solid/system/pimpl.hpp"
#include <QMainWindow>
#include <functional>
#include <string>
#include <vector>

namespace myapps {
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
    using ForgotFunctionT = std::function<bool(const std::string&, const std::string&)>;
    using ResetFunctionT = std::function<bool(const std::string&, const std::string&, const std::string&)>;
    using DeleteAccountFunctionT = std::function<bool(const std::string&, const std::string&)>;

    QString                 login_;
    AuthenticateFunctionT authenticate_fnc_;
    CreateFunctionT       create_fnc_;
    AmendFunctionT        amend_fnc_;
    ValidateFunctionT     validate_fnc_;
    ResendValidateFunctionT resend_validate_fnc_;
    AuthFetchFunctionT      auth_fetch_fnc_;
    LogoutFunctionT         logout_fnc_;
    ForgotFunctionT         forgot_fnc_;
    ResetFunctionT          reset_fnc_;
    DeleteAccountFunctionT  delete_account_fnc_;
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
    void onDeleteAccountResponse(const std::string& _error);
 
signals:
    void closeSignal();
    void onlineSignal(bool);
    //void authSignal(bool);
    void authSignal(const QString&);
    void authValidateSignal();

    void captchaSignal(CaptchaPointerT);
    void amendFetchSignal(AmendFetchPointerT);
    void emailValidationResentSignal();
    void deleteAccountSignal(const QString&);

private slots:
    void onAuthClick();
    void onLogoutClick();
    void onCreateClick();
    void onValidateClick();
    void onAmendClick();
    void onResetClick();
    void onValidateResendClick();
    void onForgotClick();
    void onResetPasswordClick();

    void onOnline(bool);
    void onAuthSlot(const QString&);
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
    void amendLineEdited(const QString& text);
    void amendTextEdited();
    void resetTextEdited(const QString& text);
    void emailValidationResentSlot();
    void editAccountOptionChanged(bool checked);

    void deleteAccountSlot(const QString& error);

    void onColorSchemeChanged(Qt::ColorScheme scheme);

private:
    void closeEvent(QCloseEvent*) override;
    bool eventFilter(QObject* obj, QEvent* event) override;

private:
    struct Data;
    solid::PimplT<Data> pimpl_;
};
} //namespace auth
} //namespace client
} //namespace myapps

Q_DECLARE_METATYPE(myapps::client::auth::CaptchaPointerT);
Q_DECLARE_METATYPE(myapps::client::auth::AmendFetchPointerT);
