#include "gui_auth_widget.hpp"
#include "ui_gui_auth_form.h"

namespace ola {
namespace client {
namespace gui {

struct AuthWidget::Data {
    Ui::AuthForm form_;
};

AuthWidget::AuthWidget(QWidget* parent)
    : QWidget(parent)
    , pimpl_(solid::make_pimpl<Data>())
{
    pimpl_->form_.setupUi(this);
}

AuthWidget::~AuthWidget() {}

void AuthWidget::setUser(const std::string& _user) {
}

void AuthWidget::start()
{
    this->show();
}

} //namespace gui
} //namespace client
} //namespace ola
