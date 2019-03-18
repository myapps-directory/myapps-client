#include "gui_auth_widget.hpp"

namespace ola{
namespace client{
namespace gui{

AuthWidget::AuthWidget(QWidget *parent): QWidget(parent){}

void AuthWidget::start(){
    this->show();
}

}//namespace gui
}//namespace client
}//namespace ola
