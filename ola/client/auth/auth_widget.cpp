#include "auth_widget.hpp"
#include "ui_auth_form.h"
#include "ui_main_form.h"
#include <QKeyEvent>
#include <QToolBar>
#include <QToolButton>

#include <stdio.h>
#include <windows.h>
#pragma comment(lib, "user32.lib")

#include "solid/system/log.hpp"

namespace ola {
namespace client {
namespace auth {
namespace {
const solid::LoggerT logger("ola::client::auth::widget");
}

struct Widget::Data {
    Ui::MainWindow           main_form_;
    Ui::AuthForm             auth_form_;
    TryAuthenticateFunctionT auth_fnc_;
    QToolBar                 tool_bar_;
    QAction                  back_action_;
    QAction                  home_action_;
    QAction                  create_action_;

    Data(QMainWindow* _pw)
        : tool_bar_(_pw)
        , back_action_(QIcon(":/images/back.png"), tr("&Back"), _pw)
        , home_action_(QIcon(":/images/home.png"), tr("&Home"), _pw) 
        , create_action_(QIcon(":/images/create.png"), tr("&Create"), _pw) 
    {
    }

    void showWidget(QWidget* _pmain, QWidget* _pw)
    {
        if (main_form_.authWidget != _pw) {
            main_form_.authWidget->hide();
        }
        if (main_form_.createWidget != _pw) {
            main_form_.createWidget->hide();
        }
        if (main_form_.aboutWidget != _pw) {
            main_form_.aboutWidget->hide();
        }
        _pw->show();
        const int h = _pw->height() + tool_bar_.height() + main_form_.label->height();
        _pmain->setFixedSize(QSize(_pw->width(), h));
    }
};

Widget::Widget(QWidget* parent)
    : QMainWindow(parent)
    , pimpl_(solid::make_pimpl<Data>(this))
{
    setWindowFlags(windowFlags() & (~Qt::WindowMaximizeButtonHint));

    pimpl_->main_form_.setupUi(this);
    pimpl_->auth_form_.setupUi(pimpl_->main_form_.authWidget);
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
    connect(this, SIGNAL(offlineSignal(bool)), this, SLOT(onOffline(bool)), Qt::QueuedConnection);
    connect(this, SIGNAL(authFailSignal()), this, SLOT(onAuthFail()), Qt::QueuedConnection);
    connect(this, SIGNAL(authSuccessSignal()), this, SLOT(onAuthSuccess()), Qt::QueuedConnection);
    connect(this, SIGNAL(closeSignal()), this, SLOT(close()), Qt::QueuedConnection);

    pimpl_->tool_bar_.setMovable(false);
    pimpl_->tool_bar_.setFixedHeight(38);
    //pimpl_->tool_bar_.setContentsMargins(QMargins(0, 0, 0, 0));
    pimpl_->tool_bar_.setIconSize(QSize(32, 32));
    
    pimpl_->tool_bar_.setStyleSheet("QToolBar { border: 0px }");
    //pimpl_->tool_bar_.setStyleSheet("QToolBar { icon-size: 32px 32px}");
    //pimpl_->tool_bar_.addSeparator();
    pimpl_->tool_bar_.addAction(&pimpl_->back_action_);
    pimpl_->tool_bar_.addAction(&pimpl_->home_action_);
    pimpl_->tool_bar_.addAction(&pimpl_->create_action_);

    this->addToolBar(&pimpl_->tool_bar_);

    pimpl_->showWidget(this, pimpl_->main_form_.authWidget);
}

Widget::~Widget() {}

void Widget::setUser(const std::string& _user)
{
    solid_log(logger, Info, "" << _user);
    pimpl_->auth_form_.userEdit->setText(_user.c_str());
}

void Widget::start(TryAuthenticateFunctionT&& _auth_fnc)
{
    pimpl_->auth_fnc_ = std::move(_auth_fnc);
    this->show();
}

void Widget::onAuthClick()
{
    solid_log(logger, Verbose, "");
    if (!pimpl_->auth_form_.passwordEdit->text().isEmpty() && !pimpl_->auth_form_.userEdit->text().isEmpty()) {
        this->setEnabled(false);
        //close();
        pimpl_->auth_fnc_(pimpl_->auth_form_.userEdit->text().toStdString(), pimpl_->auth_form_.passwordEdit->text().toStdString());
    } else {
        pimpl_->main_form_.label->setText("Please provide an user name and a password");
    }
}

void Widget::onOffline(bool _b)
{
    solid_log(logger, Verbose, "" << _b);
    if (_b) {
        pimpl_->main_form_.label->setText("Offline...");
    } else {
        pimpl_->main_form_.label->setText("Online...");
    }
}

void Widget::onAuthFail()
{
    solid_log(logger, Verbose, "");

    pimpl_->main_form_.label->setText("Failed authentication");
    pimpl_->auth_form_.passwordEdit->setText("");
    this->setEnabled(true);
}
void Widget::onAuthSuccess()
{
    solid_log(logger, Verbose, "");
    pimpl_->main_form_.label->setText("Succes");
}

void Widget::closeEvent(QCloseEvent*)
{
    QApplication::quit();
}
bool Widget::eventFilter(QObject* obj, QEvent* event)
{
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent* key = static_cast<QKeyEvent*>(event);
        if ((key->key() == Qt::Key_Enter) || (key->key() == Qt::Key_Return)) {
            onAuthClick();
        } else {
            return QObject::eventFilter(obj, event);
        }
        return true;
    } else {
        return QObject::eventFilter(obj, event);
    }
    return false;
}

} //namespace auth
} //namespace client
} //namespace ola
