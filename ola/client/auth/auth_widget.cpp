#include "auth_widget.hpp"
#include "ui_auth_form.h"
#include <QKeyEvent>

#include "solid/system/log.hpp"

namespace ola {
namespace client {
namespace auth {
namespace {
const solid::LoggerT logger("ola::client::auth::widget");
}

struct Widget::Data {
    Ui::AuthForm             form_;
    TryAuthenticateFunctionT auth_fnc_;
};

Widget::Widget(QWidget* parent)
    : QWidget(parent)
    , pimpl_(solid::make_pimpl<Data>())
{
    pimpl_->form_.setupUi(this);
    setWindowFlags(Qt::Drawer);

    installEventFilter(this);

    connect(pimpl_->form_.authButton, SIGNAL(clicked()), this, SLOT(onAuthClick()));
    connect(this, SIGNAL(offlineSignal(bool)), this, SLOT(onOffline(bool)), Qt::QueuedConnection);
    connect(this, SIGNAL(authFailSignal()), this, SLOT(onAuthFail()), Qt::QueuedConnection);
    connect(this, SIGNAL(authSuccessSignal()), this, SLOT(onAuthSuccess()), Qt::QueuedConnection);
    connect(this, SIGNAL(closeSignal()), this, SLOT(close()), Qt::QueuedConnection);
}

Widget::~Widget() {}

void Widget::setUser(const std::string& _user)
{
    solid_log(logger, Info, "" << _user);
    pimpl_->form_.userEdit->setText(_user.c_str());
}

void Widget::start(TryAuthenticateFunctionT&& _auth_fnc)
{
    pimpl_->auth_fnc_ = std::move(_auth_fnc);
    this->show();
}

void Widget::onAuthClick()
{
    solid_log(logger, Verbose, "");
    if (!pimpl_->form_.passwordEdit->text().isEmpty() && !pimpl_->form_.userEdit->text().isEmpty()) {
        this->setEnabled(false);
        //close();
        pimpl_->auth_fnc_(pimpl_->form_.userEdit->text().toStdString(), pimpl_->form_.passwordEdit->text().toStdString());
    } else {
        pimpl_->form_.label->setText("Please provide an user name and a password");
    }
}

void Widget::onOffline(bool _b)
{
    solid_log(logger, Verbose, "" << _b);
    if (_b) {
        pimpl_->form_.label->setText("Offline...");
    } else {
        pimpl_->form_.label->setText("Online...");
    }
}

void Widget::onAuthFail()
{
    solid_log(logger, Verbose, "");

    pimpl_->form_.label->setText("Failed authentication");
    pimpl_->form_.passwordEdit->setText("");
    this->setEnabled(true);
}
void Widget::onAuthSuccess()
{
    solid_log(logger, Verbose, "");
    pimpl_->form_.label->setText("Succes");
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
