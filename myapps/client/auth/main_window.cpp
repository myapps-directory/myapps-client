// myapps/client/auth/main_window.cpp

// This file is part of MyApps.directory project
// Copyright (C) 2020, 2021, 2022, 2023, 2024, 2025 Valentin Palade (vipalade @ gmail . com)

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// at your option any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "main_window.hpp"
#include "ui_about_form.h"
#include "ui_amend_form.h"
#include "ui_create_form.h"
#include "ui_home_form.h"
#include "ui_main_form.h"
#include "ui_reset_form.h"
#include <QKeyEvent>
#include <QMessageBox>
#include <QStyleHints>
#include <QToolBar>
#include <QToolButton>

#include <chrono>
#include <iomanip>
#include <regex>
#include <sstream>
#include <stack>
#include <stdio.h>
#include <string>
#include <windows.h>
#pragma comment(lib, "user32.lib")

#include "myapps/common/utility/version.hpp"

#include "solid/system/log.hpp"

namespace myapps {
namespace client {
namespace auth {
namespace {
const solid::LoggerT logger("myapps::client::auth::widget");

enum struct ActionE {
    Home = 0,
    Create,
    About,
    Amend,
    Reset,
};

using HistoryFunctionT = std::function<void()>;
struct HistoryStub {
    HistoryFunctionT func_;
    ActionE          action_;

    template <class F>
    HistoryStub(
        const ActionE _action,
        F             _f)
        : func_(_f)
        , action_(_action)
    {
    }
};
using HistoryStackT = std::stack<HistoryStub>;

} // namespace
struct MainWindow::Data {
    Ui::MainWindow main_form_;
    Ui::HomeForm   home_form_;
    Ui::CreateForm create_form_;
    Ui::AboutForm  about_form_;
    Ui::AmendForm  amend_form_;
    Ui::ResetForm  reset_form_;
    Configuration  config_;
    QToolBar       tool_bar_;
    QAction        back_action_;
    QAction        home_action_;
    QAction        create_action_;
    QAction        about_action_;
    QAction        amend_action_;
    HistoryStackT  history_;
    ActionE        current_action_;
    bool           authenticated_  = false;
    bool           validate_email_ = false;
    int            dpi_x_          = QApplication::primaryScreen()->logicalDotsPerInchX();
    int            dpi_y_          = QApplication::primaryScreen()->logicalDotsPerInchY();
    double         scale_x_        = double(dpi_x_) / 120.0; // 173.0 / double(dpi_x_);
    double         scale_y_        = double(dpi_y_) / 120.0; // 166.0 / double(dpi_y_);
    const QString  login_str_{"Login"};
    const QString  demo_login_str_{"Demo Login"};

    static bool isColorSchemeDark()
    {
        return QGuiApplication::styleHints()->colorScheme() == Qt::ColorScheme::Dark;
    }

    Data(QMainWindow* _pw)
        : tool_bar_(_pw)
        , back_action_(QIcon(isColorSchemeDark() ? ":/images/back_d.png" : ":/images/back.png"), tr("&Back"), _pw)
        , home_action_(QIcon(isColorSchemeDark() ? ":/images/home_d.png" : ":/images/home.png"), tr("&Home"), _pw)
        , create_action_(QIcon(isColorSchemeDark() ? ":/images/create_d.png" : ":/images/create.png"), tr("&Create"), _pw)
        , about_action_(QIcon(isColorSchemeDark() ? ":/images/about_d.png" : ":/images/about.png"), tr("&About"), _pw)
        , amend_action_(QIcon(isColorSchemeDark() ? ":/images/amend_d.png" : ":/images/amend.png"), tr("&Edit"), _pw)
    {
    }

    void showWidget(QWidget* _pmain, QWidget* _pw)
    {
        if (main_form_.homeWidget != _pw) {
            main_form_.homeWidget->hide();
        } else {
            if (validate_email_) {
                home_form_.logoutButton->show();
                home_form_.authButton->hide();
                home_form_.userEdit->hide();
                home_form_.codeEdit->hide();
                home_form_.label->hide();
                home_form_.passwordEdit->hide();
                home_form_.validateEmailEdit->show();
                home_form_.validateEmailButton->show();
                home_form_.validateEmailResendButton->show();
                home_form_.forgotButton->hide();
                home_form_.resetButton->hide();
                amend_action_.setEnabled(true);
                create_action_.setEnabled(false);
            } else if (authenticated_) {
                // hide everything but logoutButton
                home_form_.logoutButton->show();
                home_form_.authButton->hide();
                home_form_.userEdit->hide();
                home_form_.codeEdit->hide();
                home_form_.label->hide();
                home_form_.passwordEdit->hide();
                home_form_.validateEmailEdit->hide();
                home_form_.validateEmailButton->hide();
                home_form_.validateEmailResendButton->hide();
                home_form_.forgotButton->hide();
                home_form_.resetButton->hide();
                home_form_.line->hide();
                amend_action_.setEnabled(true);
                create_action_.setEnabled(false);
            } else {
                // show everything but logoutButton
                home_form_.logoutButton->hide();
                home_form_.authButton->show();
                home_form_.userEdit->show();
                home_form_.codeEdit->show();
                home_form_.label->show();
                home_form_.passwordEdit->show();
                home_form_.forgotButton->show();
                home_form_.resetButton->show();
                home_form_.validateEmailEdit->hide();
                home_form_.validateEmailButton->hide();
                home_form_.validateEmailResendButton->hide();
                amend_action_.setEnabled(false);
                create_action_.setEnabled(true);
            }
            current_action_ = ActionE::Home;
        }
        if (main_form_.createWidget != _pw) {
            main_form_.createWidget->hide();
        } else {
            create_form_.password1Edit->clear();
            create_form_.password2Edit->clear();
            create_form_.codeEdit->clear();
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
        if (main_form_.resetWidget != _pw) {
            main_form_.resetWidget->hide();
        } else {
            current_action_ = ActionE::Reset;
        }
#if 0
        if (main_form_.validateWidget != _pw) {
            main_form_.validateWidget->hide();
        } else {
            back_action_.setEnabled(false);
            home_action_.setEnabled(false);
            create_action_.setEnabled(false);
            amend_action_.setEnabled(true);
            current_action_ = ActionE::Validate;
        }
#endif
        _pw->show();
    }

    QSize computeMaxSize() const
    {
        int maxh = 0;
        int maxw = 0;

        if (main_form_.homeWidget->width() > maxw) {
            maxw = main_form_.homeWidget->width();
        }

        int home_h = main_form_.homeWidget->height();
        home_h -= home_form_.validateEmailEdit->height();
        home_h -= home_form_.validateEmailButton->height();
        home_h -= home_form_.validateEmailResendButton->height();
        home_h -= home_form_.validateEmailResendButton->height();

        if (home_h > maxh) {
            maxh = home_h;
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

        return QSize(maxw * scale_x_, (maxh * scale_y_) + tool_bar_.height() + main_form_.label->height());
    }

    template <class F>
    HistoryFunctionT& historyPush(const ActionE _action, F _f)
    {
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
    pimpl_->home_form_.setupUi(pimpl_->main_form_.homeWidget);
    pimpl_->create_form_.setupUi(pimpl_->main_form_.createWidget);
    pimpl_->about_form_.setupUi(pimpl_->main_form_.aboutWidget);
    pimpl_->amend_form_.setupUi(pimpl_->main_form_.amendWidget);
    pimpl_->reset_form_.setupUi(pimpl_->main_form_.resetWidget);

    const auto max_size = pimpl_->computeMaxSize();
    setFixedSize(max_size);
    resize(max_size);

    pimpl_->home_form_.label->setFixedSize(QSize(pimpl_->home_form_.label->width() * pimpl_->scale_x_, pimpl_->home_form_.label->height() * pimpl_->scale_y_));
    pimpl_->create_form_.label->setFixedSize(QSize(pimpl_->create_form_.label->width() * pimpl_->scale_x_, pimpl_->create_form_.label->height() * pimpl_->scale_y_));
    pimpl_->reset_form_.label->setFixedSize(QSize(pimpl_->reset_form_.label->width() * pimpl_->scale_x_, pimpl_->reset_form_.label->height() * pimpl_->scale_y_));

    if (false) {
        int   aElements[2] = {COLOR_WINDOW, COLOR_ACTIVECAPTION};
        DWORD aOldColors[2];

        aOldColors[0] = GetSysColor(aElements[0]);

        QPalette     pal = palette();
        const QColor win_color(GetRValue(aOldColors[0]), GetGValue(aOldColors[0]), GetBValue(aOldColors[0]));
        // set black background
        pal.setColor(QPalette::Window, win_color);
        setAutoFillBackground(true);
        setPalette(pal);
    }
    installEventFilter(this);

    auto* hints = QGuiApplication::styleHints();

    connect(hints, SIGNAL(colorSchemeChanged(Qt::ColorScheme)), this, SLOT(onColorSchemeChanged(Qt::ColorScheme)));

    connect(pimpl_->home_form_.authButton, SIGNAL(clicked()), this, SLOT(onAuthClick()));
    connect(pimpl_->home_form_.logoutButton, SIGNAL(clicked()), this, SLOT(onLogoutClick()));
    connect(pimpl_->create_form_.createButton, SIGNAL(clicked()), this, SLOT(onCreateClick()));
    connect(pimpl_->home_form_.validateEmailButton, SIGNAL(clicked()), this, SLOT(onValidateClick()));
    connect(pimpl_->home_form_.validateEmailResendButton, SIGNAL(clicked()), this, SLOT(onValidateResendClick()));
    connect(pimpl_->home_form_.resetButton, SIGNAL(clicked()), this, SLOT(onResetClick()));
    connect(pimpl_->home_form_.forgotButton, SIGNAL(clicked()), this, SLOT(onForgotClick()));
    connect(pimpl_->amend_form_.amendButton, SIGNAL(clicked()), this, SLOT(onAmendClick()));
    connect(pimpl_->reset_form_.resetButton, SIGNAL(clicked()), this, SLOT(onResetPasswordClick()));

    connect(this, SIGNAL(onlineSignal(bool)), this, SLOT(onOnline(bool)), Qt::QueuedConnection);
    connect(this, SIGNAL(authSignal(const QString&)), this, SLOT(onAuthSlot(const QString&)), Qt::QueuedConnection);
    ;
    connect(this, SIGNAL(authValidateSignal()), this, SLOT(onAuthValidate()), Qt::QueuedConnection);
    connect(this, SIGNAL(closeSignal()), this, SLOT(close()), Qt::QueuedConnection);
    connect(this, &MainWindow::captchaSignal, this, &MainWindow::captchaSlot, Qt::QueuedConnection);
    connect(this, &MainWindow::amendFetchSignal, this, &MainWindow::amendFetchSlot, Qt::QueuedConnection);
    connect(this, &MainWindow::emailValidationResentSignal, this, &MainWindow::emailValidationResentSlot, Qt::QueuedConnection);
    connect(this, &MainWindow::deleteAccountSignal, this, &MainWindow::deleteAccountSlot, Qt::QueuedConnection);

    connect(&pimpl_->home_action_, &QAction::triggered, this, &MainWindow::goAuthSlot);
    connect(&pimpl_->create_action_, &QAction::triggered, this, &MainWindow::goCreateSlot);
    connect(&pimpl_->back_action_, &QAction::triggered, this, &MainWindow::goBackSlot);
    connect(&pimpl_->about_action_, &QAction::triggered, this, &MainWindow::goAboutSlot);
    connect(&pimpl_->amend_action_, &QAction::triggered, this, &MainWindow::goAmendSlot);

    connect(pimpl_->home_form_.userEdit, &QLineEdit::textChanged, this, &MainWindow::authTextEdited);
    connect(pimpl_->home_form_.passwordEdit, &QLineEdit::textChanged, this, &MainWindow::authTextEdited);
    connect(pimpl_->home_form_.codeEdit, &QLineEdit::textChanged, this, &MainWindow::authTextEdited);

    connect(pimpl_->home_form_.validateEmailEdit, &QLineEdit::textChanged, this, &MainWindow::validateTextEdited);

    connect(pimpl_->create_form_.userEdit, &QLineEdit::textChanged, this, &MainWindow::createTextEdited);
    connect(pimpl_->create_form_.email1Edit, &QLineEdit::textChanged, this, &MainWindow::createTextEdited);
    connect(pimpl_->create_form_.email2Edit, &QLineEdit::textChanged, this, &MainWindow::createTextEdited);
    connect(pimpl_->create_form_.password1Edit, &QLineEdit::textChanged, this, &MainWindow::createTextEdited);
    connect(pimpl_->create_form_.password2Edit, &QLineEdit::textChanged, this, &MainWindow::createTextEdited);
    connect(pimpl_->create_form_.codeEdit, &QLineEdit::textChanged, this, &MainWindow::createTextEdited);

    connect(pimpl_->amend_form_.userEdit, &QLineEdit::textChanged, this, &MainWindow::amendLineEdited);
    connect(pimpl_->amend_form_.email1Edit, &QLineEdit::textChanged, this, &MainWindow::amendLineEdited);
    connect(pimpl_->amend_form_.email2Edit, &QLineEdit::textChanged, this, &MainWindow::amendLineEdited);
    connect(pimpl_->amend_form_.passwordEdit, &QLineEdit::textChanged, this, &MainWindow::amendLineEdited);
    connect(pimpl_->amend_form_.newPassword1Edit, &QLineEdit::textChanged, this, &MainWindow::amendLineEdited);
    connect(pimpl_->amend_form_.newPassword2Edit, &QLineEdit::textChanged, this, &MainWindow::amendLineEdited);
    connect(pimpl_->amend_form_.reasonEdit, &QTextEdit::textChanged, this, &MainWindow::amendTextEdited);
    connect(pimpl_->amend_form_.editRadioButton, &QAbstractButton::toggled, this, &MainWindow::editAccountOptionChanged);
    connect(pimpl_->amend_form_.deleteRadioButton, &QAbstractButton::toggled, this, &MainWindow::editAccountOptionChanged);

    connect(pimpl_->reset_form_.tokenEdit, &QLineEdit::textChanged, this, &MainWindow::resetTextEdited);
    connect(pimpl_->reset_form_.newPassword1Edit, &QLineEdit::textChanged, this, &MainWindow::resetTextEdited);
    connect(pimpl_->reset_form_.newPassword2Edit, &QLineEdit::textChanged, this, &MainWindow::resetTextEdited);
    connect(pimpl_->reset_form_.codeEdit, &QLineEdit::textChanged, this, &MainWindow::resetTextEdited);

    pimpl_->tool_bar_.setMovable(false);
    pimpl_->tool_bar_.setFixedHeight(38 * pimpl_->scale_y_);
    // pimpl_->tool_bar_.setContentsMargins(QMargins(0, 0, 0, 0));
    pimpl_->tool_bar_.setIconSize(QSize(32 * pimpl_->scale_x_, 32 * pimpl_->scale_y_));

    pimpl_->tool_bar_.setStyleSheet("QToolBar { border: 0px }");
    // pimpl_->tool_bar_.setStyleSheet("QToolBar { icon-size: 32px 32px}");
    //

    pimpl_->amend_action_.setEnabled(false);

    QWidget* empty = new QWidget();
    empty->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    pimpl_->tool_bar_.addAction(&pimpl_->back_action_);
    pimpl_->tool_bar_.addAction(&pimpl_->home_action_);
    pimpl_->tool_bar_.addAction(&pimpl_->create_action_);
    pimpl_->tool_bar_.addAction(&pimpl_->amend_action_);
    pimpl_->tool_bar_.addWidget(empty);
    pimpl_->tool_bar_.addSeparator();
    pimpl_->tool_bar_.addAction(&pimpl_->about_action_);

    pimpl_->home_form_.authButton->setEnabled(false);
    pimpl_->home_form_.authButton->setText(pimpl_->demo_login_str_);
    pimpl_->create_form_.createButton->setEnabled(false);
    pimpl_->home_form_.validateEmailButton->setEnabled(false);

    pimpl_->amend_form_.reasonEdit->setVisible(false);

    this->addToolBar(&pimpl_->tool_bar_);

    pimpl_->showWidget(this, pimpl_->main_form_.homeWidget);
    pimpl_->history_.emplace(
        ActionE::Home,
        [this]() {
            pimpl_->showWidget(this, pimpl_->main_form_.homeWidget);
        });

    pimpl_->about_form_.tabWidget->setCurrentIndex(0); // About
    {
        using namespace std;
        ostringstream oss;

        oss << utility::VERSION_MAJOR << '.' << utility::VERSION_MINOR;
        // oss << " - " << client::utility::version_vcs_branch();
        oss << " - <a href=https://github.com/myapps-space/myapps-client/tree/" << utility::version_vcs_commit() << ">" << utility::version_vcs_commit() << "</a>";

        pimpl_->about_form_.label_version->setText(QString::fromStdString(oss.str()));
    }
    {
        using namespace std;
        using namespace std::chrono;
        auto    now_c = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm ptm;
        localtime_s(&ptm, &now_c);

        {
            ostringstream oss;

            oss << "Copyright 2019-" << std::put_time(&ptm, "%Y") << " MyApps Co. All rights reserved." << endl;
            oss << endl;
            oss << "License <a href=https://www.gnu.org/licenses/gpl-3.0.en.html>GPL3</a>" << endl;
            oss << endl;
            oss << "The program is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE." << endl;

            pimpl_->about_form_.label_about->setText(QString::fromStdString(oss.str()));
        }
        {
            ostringstream oss;
            oss << "Open Source Software:" << endl;
            oss << endl;
            oss << " <a href=https://github.com/solidoss/solidframe>SolidFrame</a> - " << solid::VERSION_MAJOR << '.' << solid::VERSION_MINOR;
            oss << " - <a href=https://github.com/solidoss/solidframe/tree/" << solid::version_vcs_commit() << ">" << solid::version_vcs_commit() << "</a>" << endl;
            oss << endl;
            oss << " <a href=http://www.secfs.net/winfsp>WinFsp</a>" << endl;
            oss << endl;
            oss << " <a href=https://www.qt.io>Qt</a>" << endl;
            oss << endl;
            oss << " <a href=https://www.boost.org>Boost</a>" << endl;
            oss << endl;
            oss << " <a href=https://www.openssl.org>OpenSSL</a>" << endl;
            oss << endl;
            oss << " <a href=https://github.com/USCiLab/cereal>Cereal</a>" << endl;
            oss << endl;
            oss << " <a href=https://github.com/google/snappy>Snappy</a>" << endl;
            oss << endl;
            oss << " <a href=https://zlib.net>zlib</a>" << endl;
            oss << endl;
            oss << " <a href=https://libzip.org>libzip</a>" << endl;
            oss << endl;
            oss << " <a href=https://github.com/AmokHuginnsson/replxx>replxx</a>" << endl;
            oss << endl;
            oss << " <a href=https://github.com/jbeder/yaml-cpp>yaml</a>" << endl;
            oss << endl;

            pimpl_->about_form_.label_credits->setText(QString::fromStdString(oss.str()));
        }
    }
}

MainWindow::~MainWindow() {}

void MainWindow::setUser(const std::string& _user)
{
    solid_log(logger, Info, "" << _user);
    pimpl_->home_form_.userEdit->setText(_user.c_str());
}

void MainWindow::start(
    Configuration&& _config)
{
    pimpl_->config_ = std::move(_config);

    pimpl_->home_form_.userEdit->setText(pimpl_->config_.login_);
    this->show();
    this->setWindowState((windowState() & ~Qt::WindowMinimized) | Qt::WindowActive);
    this->raise(); // for MacOS
    this->activateWindow(); // for Windows
}

void MainWindow::onAuthClick()
{
    solid_log(logger, Verbose, "");

    const bool ok = pimpl_->config_.authenticate_fnc_(
        pimpl_->home_form_.userEdit->text().toStdString(),
        pimpl_->home_form_.passwordEdit->text().toStdString(),
        pimpl_->home_form_.codeEdit->text().toStdString());
    if (ok) {
        pimpl_->home_form_.authButton->setEnabled(false);
    }
}

void MainWindow::onLogoutClick()
{
    pimpl_->config_.logout_fnc_();
}

void MainWindow::onCreateClick()
{
    solid_log(logger, Verbose, "");

    const bool ok = pimpl_->config_.create_fnc_(
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
    const bool ok = pimpl_->config_.validate_fnc_(pimpl_->home_form_.validateEmailEdit->text().toStdString());
    if (ok) {
        pimpl_->home_form_.validateEmailButton->setEnabled(false);
    }
}

void MainWindow::onAmendClick()
{
    if (pimpl_->amend_form_.editRadioButton->isChecked()) {
        const auto user         = pimpl_->amend_form_.userEdit->text().toStdString();
        const auto email        = pimpl_->amend_form_.email1Edit->text().toStdString();
        const auto password     = pimpl_->amend_form_.passwordEdit->text().toStdString();
        const auto new_password = pimpl_->amend_form_.newPassword1Edit->text().toStdString();

        const bool ok = pimpl_->config_.amend_fnc_(user, email, password, new_password);
        if (ok) {
            pimpl_->amend_form_.amendButton->setEnabled(false);
            pimpl_->amend_form_.passwordEdit->setText("");
            pimpl_->amend_form_.newPassword1Edit->setText("");
            pimpl_->amend_form_.newPassword2Edit->setText("");
        }
    } else if (pimpl_->amend_form_.deleteRadioButton->isChecked()) {
        QMessageBox msgBox;
        msgBox.setText("We're sorry to loose you as a client.\nThank you for your feedback.");
        msgBox.setInformativeText("If you change your mind, press Cancel, otherwise press Ok and you will be disconnected on all MyApps instances!");
        msgBox.setStandardButtons(QMessageBox::Cancel | QMessageBox::Ok);
        msgBox.setDefaultButton(QMessageBox::Cancel);
        msgBox.setIcon(QMessageBox::Critical);
        int ret = msgBox.exec();
        if (ret == QMessageBox::Ok) {
            const auto password = pimpl_->amend_form_.passwordEdit->text().toStdString();
            const auto reason   = pimpl_->amend_form_.reasonEdit->toPlainText().toStdString();
            pimpl_->config_.delete_account_fnc_(password, reason);
        }
    }
}

void MainWindow::onResetClick()
{
    pimpl_->showWidget(this, pimpl_->main_form_.resetWidget);
}

void MainWindow::onValidateResendClick()
{
    if (pimpl_->config_.resend_validate_fnc_()) {
        pimpl_->home_form_.validateEmailResendButton->setEnabled(false);
    }
}

void MainWindow::onForgotClick()
{
    const auto user = pimpl_->home_form_.userEdit->text().toStdString();
    const auto code = pimpl_->home_form_.codeEdit->text().toStdString();

    const bool ok = pimpl_->config_.forgot_fnc_(user, code);
    if (ok) {
        pimpl_->home_form_.forgotButton->setEnabled(false);
    }
}

void MainWindow::onResetPasswordClick()
{
    const auto token = pimpl_->reset_form_.tokenEdit->text().toStdString();
    const auto pass  = pimpl_->reset_form_.newPassword1Edit->text().toStdString();
    const auto code  = pimpl_->reset_form_.codeEdit->text().toStdString();

    const bool ok = pimpl_->config_.reset_fnc_(token, pass, code);
    if (ok) {
        pimpl_->reset_form_.resetButton->setEnabled(false);
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

void MainWindow::onAuthSlot(const QString& _error)
{
    solid_log(logger, Verbose, "" << _error.toStdString());

    pimpl_->authenticated_ = _error.isEmpty();
    if (_error.isEmpty()) {
        if (pimpl_->validate_email_) {
            pimpl_->validate_email_ = false;
            pimpl_->home_form_.userEdit->setText(pimpl_->create_form_.userEdit->text());
        }
        pimpl_->main_form_.label->setText("Logged in");
        while (!pimpl_->history_.empty()) {
            pimpl_->history_.pop();
        }
    } else {
        if (pimpl_->current_action_ == ActionE::Create) {
            pimpl_->main_form_.label->setText("Invalid user + e-mail combination!");
            pimpl_->create_form_.codeEdit->clear();
            pimpl_->create_form_.password1Edit->clear();
            pimpl_->create_form_.password2Edit->clear();
            QMessageBox msgBox;
            msgBox.setText("Invalid user + e-mail combination!");
            msgBox.exec();
            pimpl_->create_form_.userEdit->setFocus();
            return;
        } else {
            {
                QMessageBox msgBox;
                msgBox.setText(_error);
                msgBox.exec();
            }
            pimpl_->validate_email_ = false;
            pimpl_->main_form_.label->setText("Authentication failed");
            pimpl_->home_form_.passwordEdit->setText("");
            pimpl_->home_form_.codeEdit->setText("");
            this->setEnabled(true);
        }
    }

    pimpl_->historyPush(ActionE::Home, [this]() {
        pimpl_->showWidget(this, pimpl_->main_form_.homeWidget);
    })();
}

void MainWindow::onAuthValidate()
{
    pimpl_->validate_email_ = true;
    pimpl_->home_form_.validateEmailEdit->setText("");
    pimpl_->showWidget(this, pimpl_->main_form_.homeWidget);
}

void MainWindow::closeEvent(QCloseEvent*)
{
    QApplication::quit();
}

void MainWindow::editAccountOptionChanged(bool checked)
{
    if (!checked) {
        return; // ignore unchecked events
    }

    if (pimpl_->amend_form_.editRadioButton->isChecked()) {
        pimpl_->amend_form_.email1Edit->setVisible(true);
        pimpl_->amend_form_.email2Edit->setVisible(true);
        pimpl_->amend_form_.userEdit->setVisible(true);
        pimpl_->amend_form_.passwordEdit->setVisible(true);
        pimpl_->amend_form_.newPassword1Edit->setVisible(true);
        pimpl_->amend_form_.newPassword2Edit->setVisible(true);
        pimpl_->amend_form_.reasonEdit->setVisible(false);
    } else if (pimpl_->amend_form_.deleteRadioButton->isChecked()) {
        pimpl_->amend_form_.email1Edit->setVisible(false);
        pimpl_->amend_form_.email2Edit->setVisible(false);
        pimpl_->amend_form_.userEdit->setVisible(false);
        pimpl_->amend_form_.passwordEdit->setVisible(true);
        pimpl_->amend_form_.newPassword1Edit->setVisible(false);
        pimpl_->amend_form_.newPassword2Edit->setVisible(false);
        pimpl_->amend_form_.reasonEdit->setVisible(true);
    }
    amendTextEdited();
}

bool MainWindow::eventFilter(QObject* obj, QEvent* event)
{
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent* key = static_cast<QKeyEvent*>(event);
        if ((key->key() == Qt::Key_Enter) || (key->key() == Qt::Key_Return)) {
            switch (pimpl_->current_action_) {
            case ActionE::Home:
                if (pimpl_->validate_email_) {
                    if (pimpl_->home_form_.validateEmailButton->isEnabled()) {
                        onValidateClick();
                    }
                } else if (pimpl_->authenticated_) {
                    if (pimpl_->home_form_.logoutButton->isEnabled()) {
                        onLogoutClick();
                    }
                } else {
                    if (pimpl_->home_form_.authButton->isEnabled()) {
                        onAuthClick();
                    }
                }
                break;
            case ActionE::Create:
                if (pimpl_->create_form_.createButton->isEnabled()) {
                    onCreateClick();
                }
                break;
            case ActionE::Amend:
                if (pimpl_->amend_form_.amendButton->isEnabled()) {
                    onAmendClick();
                }
                break;
            case ActionE::Reset:
                if (pimpl_->reset_form_.resetButton->isEnabled()) {
                    onResetPasswordClick();
                }
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

void MainWindow::goAuthSlot(bool)
{
    pimpl_->historyPush(ActionE::Home, [this]() {
        pimpl_->showWidget(this, pimpl_->main_form_.homeWidget);
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

void MainWindow::goCreateSlot(bool)
{
    pimpl_->historyPush(ActionE::Create, [this]() {
        pimpl_->showWidget(this, pimpl_->main_form_.createWidget);
    })();
}

void MainWindow::goBackSlot(bool)
{
    if (!pimpl_->history_.empty()) {
        if (pimpl_->history_.size() > 1) {
            pimpl_->history_.pop();
        }
        if (!pimpl_->history_.empty()) {
            pimpl_->history_.top().func_();
        }
    }
}

void MainWindow::goAboutSlot(bool)
{
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
    ptr->user_  = QString::fromStdString(_user);
    ptr->email_ = QString::fromStdString(_email);
    emit amendFetchSignal(ptr);
}

void MainWindow::onEmailValidationResent()
{
    emit emailValidationResentSignal();
}

void MainWindow::onDeleteAccountResponse(const std::string& _error)
{
    emit deleteAccountSignal(QString::fromStdString(_error));
}

void MainWindow::deleteAccountSlot(const QString& error)
{
    if (error.isEmpty()) {
        // success
        goAuthSlot(true); // wait for disconnect from server
    } else {
        QMessageBox msgBox;
        msgBox.setText("Delete Account Failed. Please retry later.");
        msgBox.setInformativeText(error);
        msgBox.setIcon(QMessageBox::Critical);
        msgBox.exec();
    }
}

void MainWindow::onColorSchemeChanged(Qt::ColorScheme scheme)
{
    pimpl_->about_action_.setIcon(QIcon(Data::isColorSchemeDark() ? ":/images/about_d.png" : ":/images/about.png"));
    pimpl_->home_action_.setIcon(QIcon(Data::isColorSchemeDark() ? ":/images/home_d.png" : ":/images/home.png"));
    pimpl_->create_action_.setIcon(QIcon(Data::isColorSchemeDark() ? ":/images/create_d.png" : ":/images/create.png"));
    pimpl_->amend_action_.setIcon(QIcon(Data::isColorSchemeDark() ? ":/images/amend_d.png" : ":/images/amend.png"));
    pimpl_->back_action_.setIcon(QIcon(Data::isColorSchemeDark() ? ":/images/back_d.png" : ":/images/back.png"));

    QImage img = pimpl_->home_form_.label->pixmap().toImage();
    img.invertPixels(QImage::InvertRgba);

    auto pixmap = QPixmap::fromImage(img, Qt::AutoColor);
    pimpl_->home_form_.label->setPixmap(pixmap);
    pimpl_->create_form_.label->setPixmap(pixmap);
    pimpl_->reset_form_.label->setPixmap(pixmap);
}

void MainWindow::captchaSlot(CaptchaPointerT _captcha_ptr)
{
    solid_log(logger, Info, "size = " << _captcha_ptr->size());
    QImage img;
    if (img.loadFromData(reinterpret_cast<const uchar*>(_captcha_ptr->data()), _captcha_ptr->size())) {
        // if (Data::isColorSchemeDark()) {
        //     img.invertPixels(QImage::InvertRgba);
        // }
        auto pixmap = QPixmap::fromImage(img, Qt::AutoColor);

        pimpl_->home_form_.label->setPixmap(pixmap);
        pimpl_->create_form_.label->setPixmap(pixmap);
        pimpl_->reset_form_.label->setPixmap(pixmap);
        pimpl_->home_form_.label->setScaledContents(true);
        pimpl_->create_form_.label->setScaledContents(true);
        pimpl_->reset_form_.label->setScaledContents(true);
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
    // const bool is_login = !(pimpl_->home_form_.passwordEdit->text().isEmpty() || pimpl_->home_form_.userEdit->text().isEmpty() || pimpl_->home_form_.codeEdit->text().isEmpty());
    // const bool isDemo = !isLogin && (pimpl_->home_form_.passwordEdit->text().isEmpty() && pimpl_->home_form_.userEdit->text().isEmpty() && !pimpl_->home_form_.codeEdit->text().isEmpty());
    const bool has_password = !pimpl_->home_form_.passwordEdit->text().isEmpty();
    const bool has_user     = !pimpl_->home_form_.userEdit->text().isEmpty();
    const bool has_code     = !pimpl_->home_form_.codeEdit->text().isEmpty();
    const bool is_demo      = !has_user && !has_password;
    const bool is_enabled   = (is_demo && has_code) || (has_code && has_user && has_password);

    if (is_demo) {
        pimpl_->home_form_.authButton->setText(pimpl_->demo_login_str_);
    } else {
        pimpl_->home_form_.authButton->setText(pimpl_->login_str_);
    }

    pimpl_->home_form_.authButton->setEnabled(is_enabled);

    pimpl_->home_form_.forgotButton->setEnabled(!(pimpl_->home_form_.userEdit->text().isEmpty() || pimpl_->home_form_.codeEdit->text().isEmpty()));
}

namespace {
bool email_check(const std::string& _email)
{
    const std::regex pattern("(\\w+)(\\.|_)?(\\w*)@(\\w+)(\\.(\\w+))+");
    return std::regex_match(_email, pattern);
}

} // namespace

void MainWindow::createTextEdited(const QString& text)
{
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

void MainWindow::validateTextEdited(const QString& text)
{
    bool enable = true;

    enable = enable && !pimpl_->home_form_.validateEmailEdit->text().isEmpty();
    pimpl_->home_form_.validateEmailButton->setEnabled(enable);
}

void MainWindow::emailValidationResentSlot()
{
    pimpl_->home_form_.validateEmailResendButton->setEnabled(true);
}

void MainWindow::amendLineEdited(const QString& text)
{
    amendTextEdited();
}

void MainWindow::amendTextEdited()
{
    bool enable = true;
    if (pimpl_->amend_form_.editRadioButton->isChecked()) {
        enable = enable && !pimpl_->amend_form_.userEdit->text().isEmpty();
        enable = enable && !pimpl_->amend_form_.email1Edit->text().isEmpty();
        enable = enable && !pimpl_->amend_form_.passwordEdit->text().isEmpty();
        enable = enable && email_check(pimpl_->amend_form_.email1Edit->text().toStdString());
        enable = enable && pimpl_->amend_form_.email1Edit->text() == pimpl_->amend_form_.email2Edit->text();
        enable = enable && pimpl_->amend_form_.newPassword1Edit->text() == pimpl_->amend_form_.newPassword2Edit->text();
    } else if (pimpl_->amend_form_.deleteRadioButton->isChecked()) {
        enable = enable && !pimpl_->amend_form_.passwordEdit->text().isEmpty();
        enable = enable && !pimpl_->amend_form_.reasonEdit->toPlainText().isEmpty();
    }
    pimpl_->amend_form_.amendButton->setEnabled(enable);
}

void MainWindow::resetTextEdited(const QString& text)
{
    bool enable = true;

    enable = enable && !pimpl_->reset_form_.tokenEdit->text().isEmpty();
    enable = enable && !pimpl_->reset_form_.codeEdit->text().isEmpty();
    enable = enable && !pimpl_->reset_form_.newPassword1Edit->text().isEmpty();
    enable = enable && pimpl_->reset_form_.newPassword1Edit->text() == pimpl_->reset_form_.newPassword2Edit->text();

    pimpl_->reset_form_.resetButton->setEnabled(enable);
}

} // namespace auth
} // namespace client
} // namespace myapps
