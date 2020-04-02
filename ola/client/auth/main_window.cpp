#include "main_window.hpp"
#include "ui_auth_form.h"
#include "ui_main_form.h"
#include "ui_create_form.h"
#include "ui_amend_form.h"
#include "ui_validate_form.h"
#include "ui_about_form.h"
#include <QKeyEvent>
#include <QToolBar>
#include <QToolButton>

#include <string>
#include <stack>
#include <regex>
#include <stdio.h>
#include <windows.h>
#pragma comment(lib, "user32.lib")

#include "solid/system/log.hpp"

namespace ola {
namespace client {
namespace auth {
namespace {
const solid::LoggerT logger("ola::client::auth::widget");


enum struct ActionE {
    Auth = 0,
    Create,
    About,
    Amend,
    Validate,
};

using HistoryFunctionT = std::function<void()>;
struct HistoryStub {
    HistoryFunctionT func_;
    ActionE   action_;

    template <class F>
    HistoryStub(
        const ActionE _action,
        F _f
     )  : func_(_f)
        , action_(_action) {}
};
using HistoryStackT    = std::stack<HistoryStub>;

}

struct MainWindow::Data {
    Ui::MainWindow           main_form_;
    Ui::AuthForm             auth_form_;
    Ui::CreateForm           create_form_;
    Ui::AboutForm            about_form_;
    Ui::AmendForm            amend_form_;
    Ui::ValidateForm         validate_form_;
    Configuration            config_;
    QToolBar                 tool_bar_;
    QAction                  back_action_;
    QAction                  home_action_;
    QAction                  create_action_;
    QAction                  about_action_;
    QAction                  amend_action_;
    HistoryStackT            history_;
    ActionE                  current_action_;

    Data(QMainWindow* _pw)
        : tool_bar_(_pw)
        , back_action_(QIcon(":/images/back.png"), tr("&Back"), _pw)
        , home_action_(QIcon(":/images/home.png"), tr("&Home"), _pw) 
        , create_action_(QIcon(":/images/create.png"), tr("&Create"), _pw) 
        , about_action_(QIcon(":/images/about.png"), tr("&About"), _pw)
        , amend_action_(QIcon(":/images/amend.png"), tr("&Edit"), _pw) 
    {
    }

    void showWidget(QWidget* _pmain, QWidget* _pw)
    {
        if (main_form_.authWidget != _pw) {
            main_form_.authWidget->hide();
        } else {
            current_action_ = ActionE::Auth;
        }
        if (main_form_.createWidget != _pw) {
            main_form_.createWidget->hide();
        } else {
            current_action_ = ActionE::Create;
        }
        if (main_form_.aboutWidget != _pw) {
            main_form_.aboutWidget->hide();
        } else {
            current_action_ = ActionE::About;
        }
        if (main_form_.amendWidget != _pw) {
            main_form_.amendWidget->hide();
        } else {
            current_action_ = ActionE::Amend;
        }
        if (main_form_.validateWidget != _pw) {
            main_form_.validateWidget->hide();
        } else {
            back_action_.setEnabled(false);
            home_action_.setEnabled(false);
            create_action_.setEnabled(false);
            amend_action_.setEnabled(true);
            current_action_ = ActionE::Validate;
        }
        _pw->show();
    }
    
    QSize computeMaxSize() const {
        int maxh = 0;
        int maxw = 0;

        if (main_form_.authWidget->width() > maxw) {
            maxw = main_form_.authWidget->width();
        }
        if (main_form_.authWidget->height() > maxh) {
            maxh = main_form_.authWidget->height();
        }

        if (main_form_.createWidget->width() > maxw) {
            maxw = main_form_.createWidget->width();
        }
        if (main_form_.createWidget->height() > maxh) {
            maxh = main_form_.createWidget->height();
        }

        if (main_form_.aboutWidget->width() > maxw) {
            maxw = main_form_.aboutWidget->width();
        }
        if (main_form_.aboutWidget->height() > maxh) {
            maxh = main_form_.aboutWidget->height();
        }

        if (main_form_.amendWidget->width() > maxw) {
            maxw = main_form_.amendWidget->width();
        }
        if (main_form_.amendWidget->height() > maxh) {
            maxh = main_form_.amendWidget->height();
        }

        if (main_form_.validateWidget->width() > maxw) {
            maxw = main_form_.validateWidget->width();
        }
        if (main_form_.validateWidget->height() > maxh) {
            maxh = main_form_.validateWidget->height();
        }

        return QSize(maxw, maxh + tool_bar_.height() + main_form_.label->height());
    }

    template <class F>
    HistoryFunctionT& historyPush(const ActionE _action, F _f) {
        if (history_.empty() || history_.top().action_ != _action) {
            history_.emplace(_action, _f);
        } else {
            history_.top().func_ = std::move(_f);
        }
        return history_.top().func_;
    }
};

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , pimpl_(solid::make_pimpl<Data>(this))
{

    qRegisterMetaType<Uint8VectorT>("Uint8VectorT");

    setWindowFlags(windowFlags() & (~Qt::WindowMaximizeButtonHint));

    pimpl_->main_form_.setupUi(this);
    pimpl_->auth_form_.setupUi(pimpl_->main_form_.authWidget);
    pimpl_->create_form_.setupUi(pimpl_->main_form_.createWidget);
    pimpl_->about_form_.setupUi(pimpl_->main_form_.aboutWidget);
    pimpl_->amend_form_.setupUi(pimpl_->main_form_.amendWidget);
    pimpl_->validate_form_.setupUi(pimpl_->main_form_.validateWidget);

    setFixedSize(pimpl_->computeMaxSize());
    resize(pimpl_->computeMaxSize());

    //setWindowFlags(Qt::Drawer);
    //setStyleSheet("background-color:black;");
    {
        int   aElements[2] = {COLOR_WINDOW, COLOR_ACTIVECAPTION};
        DWORD aOldColors[2];

        aOldColors[0] = GetSysColor(aElements[0]); 

        QPalette pal = palette();
        const QColor win_color(GetRValue(aOldColors[0]), GetGValue(aOldColors[0]), GetBValue(aOldColors[0]));
        // set black background
        pal.setColor(QPalette::Window, win_color);
        setAutoFillBackground(true);
        setPalette(pal);
    }
    installEventFilter(this);

    connect(pimpl_->auth_form_.authButton, SIGNAL(clicked()), this, SLOT(onAuthClick()));
    connect(pimpl_->create_form_.createButton, SIGNAL(clicked()), this, SLOT(onCreateClick()));
    connect(pimpl_->validate_form_.validateButton, SIGNAL(clicked()), this, SLOT(onValidateClick()));
    connect(pimpl_->validate_form_.resendButton, SIGNAL(clicked()), this, SLOT(onValidateResendClick()));
    connect(pimpl_->amend_form_.amendButton, SIGNAL(clicked()), this, SLOT(onAmendClick()));

    connect(this, SIGNAL(onlineSignal(bool)), this, SLOT(onOnline(bool)), Qt::QueuedConnection);
    connect(this, SIGNAL(authFailSignal()), this, SLOT(onAuthFail()), Qt::QueuedConnection);
    connect(this, SIGNAL(authSuccessSignal()), this, SLOT(onAuthSuccess()), Qt::QueuedConnection);
    connect(this, SIGNAL(authValidateSignal()), this, SLOT(onAuthValidate()), Qt::QueuedConnection);
    connect(this, SIGNAL(closeSignal()), this, SLOT(close()), Qt::QueuedConnection);
    connect(this, &MainWindow::captchaSignal, this, &MainWindow::captchaSlot, Qt::QueuedConnection);
    connect(this, &MainWindow::amendFetchSignal, this, &MainWindow::amendFetchSlot, Qt::QueuedConnection);
    connect(this, &MainWindow::emailValidationResentSignal, this, &MainWindow::emailValidationResentSlot, Qt::QueuedConnection);

    connect(&pimpl_->home_action_, &QAction::triggered, this, &MainWindow::goAuthSlot);
    connect(&pimpl_->create_action_, &QAction::triggered, this, &MainWindow::goCreateSlot);
    connect(&pimpl_->back_action_, &QAction::triggered, this, &MainWindow::goBackSlot);
    connect(&pimpl_->about_action_, &QAction::triggered, this, &MainWindow::goAboutSlot);
    connect(&pimpl_->amend_action_, &QAction::triggered, this, &MainWindow::goAmendSlot);

    connect(pimpl_->auth_form_.userEdit, &QLineEdit::textChanged, this, &MainWindow::authTextEdited);
    connect(pimpl_->auth_form_.passwordEdit, &QLineEdit::textChanged, this, &MainWindow::authTextEdited);
    connect(pimpl_->auth_form_.codeEdit, &QLineEdit::textChanged, this, &MainWindow::authTextEdited);

    connect(pimpl_->create_form_.userEdit, &QLineEdit::textChanged, this, &MainWindow::createTextEdited);
    connect(pimpl_->create_form_.email1Edit, &QLineEdit::textChanged, this, &MainWindow::createTextEdited);
    connect(pimpl_->create_form_.email2Edit, &QLineEdit::textChanged, this, &MainWindow::createTextEdited);
    connect(pimpl_->create_form_.password1Edit, &QLineEdit::textChanged, this, &MainWindow::createTextEdited);
    connect(pimpl_->create_form_.password2Edit, &QLineEdit::textChanged, this, &MainWindow::createTextEdited);
    connect(pimpl_->create_form_.codeEdit, &QLineEdit::textChanged, this, &MainWindow::createTextEdited);

    connect(pimpl_->amend_form_.userEdit, &QLineEdit::textChanged, this, &MainWindow::amendTextEdited);
    connect(pimpl_->amend_form_.email1Edit, &QLineEdit::textChanged, this, &MainWindow::amendTextEdited);
    connect(pimpl_->amend_form_.email2Edit, &QLineEdit::textChanged, this, &MainWindow::amendTextEdited);
    connect(pimpl_->amend_form_.passwordEdit, &QLineEdit::textChanged, this, &MainWindow::amendTextEdited);
    connect(pimpl_->amend_form_.newPassword1Edit, &QLineEdit::textChanged, this, &MainWindow::amendTextEdited);
    connect(pimpl_->amend_form_.newPassword2Edit, &QLineEdit::textChanged, this, &MainWindow::amendTextEdited);

    pimpl_->tool_bar_.setMovable(false);
    pimpl_->tool_bar_.setFixedHeight(38);
    //pimpl_->tool_bar_.setContentsMargins(QMargins(0, 0, 0, 0));
    pimpl_->tool_bar_.setIconSize(QSize(32, 32));
    
    pimpl_->tool_bar_.setStyleSheet("QToolBar { border: 0px }");
    //pimpl_->tool_bar_.setStyleSheet("QToolBar { icon-size: 32px 32px}");
    //

    pimpl_->amend_action_.setEnabled(false);

    pimpl_->tool_bar_.addAction(&pimpl_->back_action_);
    pimpl_->tool_bar_.addAction(&pimpl_->home_action_);
    pimpl_->tool_bar_.addAction(&pimpl_->create_action_);
    pimpl_->tool_bar_.addAction(&pimpl_->amend_action_);
    pimpl_->tool_bar_.addSeparator();
    pimpl_->tool_bar_.addAction(&pimpl_->about_action_);

    pimpl_->auth_form_.authButton->setEnabled(false);
    pimpl_->create_form_.createButton->setEnabled(false);

    this->addToolBar(&pimpl_->tool_bar_);

    pimpl_->showWidget(this, pimpl_->main_form_.authWidget);
    pimpl_->history_.emplace(
        ActionE::Auth,
        [this]() {
            pimpl_->showWidget(this, pimpl_->main_form_.authWidget);
        });
}

MainWindow::~MainWindow() {}

void MainWindow::setUser(const std::string& _user)
{
    solid_log(logger, Info, "" << _user);
    pimpl_->auth_form_.userEdit->setText(_user.c_str());
}

void MainWindow::start(
    Configuration &&_config)
{
    pimpl_->config_ = std::move(_config);

    pimpl_->auth_form_.userEdit->setText(pimpl_->config_.login_);
    this->show();
}

void MainWindow::onAuthClick()
{
    solid_log(logger, Verbose, "");
    
    bool ok = pimpl_->config_.authenticate_fnc_(
        pimpl_->auth_form_.userEdit->text().toStdString(),
        pimpl_->auth_form_.passwordEdit->text().toStdString(),
        pimpl_->auth_form_.codeEdit->text().toStdString()
    );
    if (ok) {
        pimpl_->auth_form_.authButton->setEnabled(false);
    }
}

void MainWindow::onCreateClick()
{
    solid_log(logger, Verbose, "");
    
    bool ok = pimpl_->config_.create_fnc_(
        pimpl_->create_form_.userEdit->text().toStdString(),
        pimpl_->create_form_.email1Edit->text().toStdString(),
        pimpl_->create_form_.password1Edit->text().toStdString(),
        pimpl_->create_form_.codeEdit->text().toStdString());
    if (ok) {
        pimpl_->create_form_.createButton->setEnabled(false);
    }
}

void MainWindow::onValidateClick()
{
    bool ok = pimpl_->config_.validate_fnc_(pimpl_->validate_form_.validateEdit->text().toStdString());
    if (ok) {
        pimpl_->validate_form_.validateButton->setEnabled(false);
    }
}

void MainWindow::onAmendClick()
{
    auto user = pimpl_->amend_form_.userEdit->text().toStdString();
    auto email = pimpl_->amend_form_.email1Edit->text().toStdString();
    auto password = pimpl_->amend_form_.passwordEdit->text().toStdString();
    auto new_password = pimpl_->amend_form_.newPassword1Edit->text().toStdString();

    bool ok = pimpl_->config_.amend_fnc_(user, email, password, new_password);
    if (ok) {
        pimpl_->amend_form_.amendButton->setEnabled(false);
        pimpl_->amend_form_.passwordEdit->setText("");
        pimpl_->amend_form_.newPassword1Edit->setText("");
        pimpl_->amend_form_.newPassword2Edit->setText("");
    }
}

void MainWindow::onValidateResendClick()
{
    if (pimpl_->config_.resend_validate_fnc_()) {
        pimpl_->validate_form_.resendButton->setEnabled(false);
    }
}

void MainWindow::onOnline(bool _b)
{
    solid_log(logger, Verbose, "" << _b);
    if (_b) {
        pimpl_->main_form_.label->setText("Online...");
    } else {
        pimpl_->main_form_.label->setText("Offline...");
    }
}

void MainWindow::onAuthFail()
{
    solid_log(logger, Verbose, "");

    pimpl_->main_form_.label->setText("Failed authentication");
    pimpl_->auth_form_.passwordEdit->setText("");
    pimpl_->auth_form_.codeEdit->setText("");
    this->setEnabled(true);
}
void MainWindow::onAuthSuccess()
{
    solid_log(logger, Verbose, "");
    pimpl_->main_form_.label->setText("Succes");
}

void MainWindow::onAuthValidate()
{
    pimpl_->showWidget(this, pimpl_->main_form_.validateWidget);
}

void MainWindow::closeEvent(QCloseEvent*)
{
    QApplication::quit();
}

bool MainWindow::eventFilter(QObject* obj, QEvent* event)
{
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent* key = static_cast<QKeyEvent*>(event);
        if ((key->key() == Qt::Key_Enter) || (key->key() == Qt::Key_Return)) {
            switch (pimpl_->current_action_) {
            case ActionE::Auth:
                onAuthClick();
                break;
            case ActionE::Create:
                onCreateClick();
                break;
            case ActionE::Amend:
                onAmendClick();
                break;
            case ActionE::Validate:
                onValidateClick();
                break;
            default:
                break;
            }
        } else {
            return QObject::eventFilter(obj, event);
        }
        return true;
    } else {
        return QObject::eventFilter(obj, event);
    }
    return false;
}

void MainWindow::goAuthSlot(bool) {
    pimpl_->historyPush(ActionE::Auth, [this]() {
        pimpl_->showWidget(this, pimpl_->main_form_.authWidget);
    })();
}

void MainWindow::goAmendSlot(bool)
{
    pimpl_->historyPush(ActionE::Amend, [this]() {
        if (pimpl_->current_action_ != ActionE::Amend) {
            if (pimpl_->config_.auth_fetch_fnc_()) {
                pimpl_->main_form_.amendWidget->setEnabled(false);
                pimpl_->showWidget(this, pimpl_->main_form_.amendWidget);
            }
        }
    })();
}

void MainWindow::goCreateSlot(bool) {
    pimpl_->historyPush(ActionE::Create, [this]() {
        pimpl_->showWidget(this, pimpl_->main_form_.createWidget);
    })();
}

void MainWindow::goBackSlot(bool) {
    if (!pimpl_->history_.empty()) {
        if (pimpl_->history_.size() > 1) {
            pimpl_->history_.pop();
        }
        if (!pimpl_->history_.empty()) {
            pimpl_->history_.top().func_();
        }
    }
}

void MainWindow::goAboutSlot(bool) {
    pimpl_->historyPush(ActionE::About, [this]() {
        pimpl_->showWidget(this, pimpl_->main_form_.aboutWidget);
    })();
}

void MainWindow::onCaptcha(Uint8VectorT&& _captcha_image)
{
    Uint8VectorT*   pvec = new std::vector<uint8_t>(std::move(_captcha_image));
    CaptchaPointerT ptr(pvec);
    emit            captchaSignal(ptr);
}

void MainWindow::onAmendFetch(const std::string& _user, const std::string& _email)
{
    AmendFetchPointerT ptr(new AmendFetch);
    ptr->user_ = QString::fromStdString(_user);
    ptr->email_ = QString::fromStdString(_email);
    emit amendFetchSignal(ptr);
}

void MainWindow::onEmailValidationResent()
{
    emit emailValidationResentSignal();
}

void MainWindow::captchaSlot(CaptchaPointerT _captcha_ptr)
{
    solid_log(logger, Info, "size = " << _captcha_ptr->size());
    QImage img;
    if (img.loadFromData(reinterpret_cast<const uchar*>(_captcha_ptr->data()), _captcha_ptr->size())) {
        pimpl_->auth_form_.label->setPixmap(QPixmap::fromImage(img, Qt::AutoColor));
        pimpl_->create_form_.label->setPixmap(QPixmap::fromImage(img, Qt::AutoColor));
    }
}

void MainWindow::amendFetchSlot(AmendFetchPointerT _amend_fetch_ptr)
{
    pimpl_->amend_form_.userEdit->setText(_amend_fetch_ptr->user_);
    pimpl_->amend_form_.email1Edit->setText(_amend_fetch_ptr->email_);
    pimpl_->amend_form_.email2Edit->setText(_amend_fetch_ptr->email_);

    pimpl_->main_form_.amendWidget->setEnabled(true);
}

void MainWindow::authTextEdited(const QString& text)
{
    pimpl_->auth_form_.authButton->setEnabled(!(pimpl_->auth_form_.passwordEdit->text().isEmpty() || pimpl_->auth_form_.userEdit->text().isEmpty() || pimpl_->auth_form_.codeEdit->text().isEmpty()));
}

namespace {
bool email_check(const std::string &_email)
{
    const std::regex pattern("(\\w+)(\\.|_)?(\\w*)@(\\w+)(\\.(\\w+))+");
    return std::regex_match(_email, pattern);
}

}//namespace

void MainWindow::createTextEdited(const QString& text) {
    bool enable = true;

    enable = enable && !pimpl_->create_form_.userEdit->text().isEmpty();
    enable = enable && !pimpl_->create_form_.email1Edit->text().isEmpty();
    enable = enable && !pimpl_->create_form_.password1Edit->text().isEmpty();
    enable = enable && !pimpl_->create_form_.password2Edit->text().isEmpty();
    enable = enable && !pimpl_->create_form_.codeEdit->text().isEmpty();
    enable = enable && pimpl_->create_form_.password1Edit->text() == pimpl_->create_form_.password2Edit->text();
    enable = enable && email_check(pimpl_->create_form_.email1Edit->text().toStdString());
    enable = enable && pimpl_->create_form_.email1Edit->text() == pimpl_->create_form_.email2Edit->text();

    pimpl_->create_form_.createButton->setEnabled(enable);
}

void MainWindow::validateTextEdited(const QString& text) {
    bool enable = true;

    enable = enable && !pimpl_->create_form_.userEdit->text().isEmpty();
    pimpl_->validate_form_.validateButton->setEnabled(enable);
}

void MainWindow::emailValidationResentSlot()
{
    pimpl_->validate_form_.resendButton->setEnabled(true);
}

void MainWindow::amendTextEdited(const QString& text)
{
    bool enable = true;

    enable = enable && !pimpl_->amend_form_.userEdit->text().isEmpty();
    enable = enable && !pimpl_->amend_form_.email1Edit->text().isEmpty();
    enable = enable && !pimpl_->amend_form_.passwordEdit->text().isEmpty();
    enable = enable && email_check(pimpl_->amend_form_.email1Edit->text().toStdString());
    enable = enable && pimpl_->amend_form_.email1Edit->text() == pimpl_->amend_form_.email2Edit->text();
    enable = enable && pimpl_->amend_form_.newPassword1Edit->text() == pimpl_->amend_form_.newPassword2Edit->text();

    pimpl_->amend_form_.amendButton->setEnabled(enable);
}

} //namespace auth
} //namespace client
} //namespace ola
