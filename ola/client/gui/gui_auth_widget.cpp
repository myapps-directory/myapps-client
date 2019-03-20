#include "gui_auth_widget.hpp"
#include "ui_gui_auth_form.h"

#include "solid/system/log.hpp"

namespace ola {
namespace client {
namespace gui {
namespace {
const solid::LoggerT logger("ola::client::gui::widget");
}

struct AuthWidget::Data {
    Ui::AuthForm             form_;
    TryAuthenticateFunctionT auth_fnc_;
};

AuthWidget::AuthWidget(QWidget* parent)
    : QWidget(parent)
    , pimpl_(solid::make_pimpl<Data>())
{
    pimpl_->form_.setupUi(this);
    setWindowFlags(Qt::Drawer);
    connect(pimpl_->form_.authButton, SIGNAL(clicked()), this, SLOT(onAuthClick()));
    connect(this, SIGNAL(offlineSignal(bool)), this, SLOT(onOffline(bool)), Qt::QueuedConnection);
    connect(this, SIGNAL(authFailSignal()), this, SLOT(onAuthFail()), Qt::QueuedConnection);
    connect(this, SIGNAL(authSuccessSignal()), this, SLOT(onAuthSuccess()), Qt::QueuedConnection);
    connect(this, SIGNAL(closeSignal()), this, SLOT(close()), Qt::QueuedConnection);
}

AuthWidget::~AuthWidget() {}

void AuthWidget::setUser(const std::string& _user)
{
    solid_log(logger, Info, "" << _user);
    pimpl_->form_.userEdit->setText(_user.c_str());
}

void AuthWidget::start(TryAuthenticateFunctionT&& _auth_fnc)
{
    pimpl_->auth_fnc_ = std::move(_auth_fnc);
    this->show();
}

void AuthWidget::onAuthClick()
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

void AuthWidget::onOffline(bool _b)
{
    solid_log(logger, Verbose, ""<<_b);
    if (_b) {
        pimpl_->form_.label->setText("Offline...");
    } else {
        pimpl_->form_.label->setText("Online...");
	}
}

void AuthWidget::onAuthFail()
{
    solid_log(logger, Verbose, "");
    
    pimpl_->form_.label->setText("Failed authentication");
    pimpl_->form_.passwordEdit->setText("");
    this->setEnabled(true);
}
void AuthWidget::onAuthSuccess()
{
    solid_log(logger, Verbose, "");
    pimpl_->form_.label->setText("Succes");
}

void AuthWidget::closeEvent(QCloseEvent*) {
    QApplication::quit();
}

} //namespace gui
} //namespace client
} //namespace ola
