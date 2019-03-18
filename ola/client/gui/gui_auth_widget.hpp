#pragma once

#include <QWidget>

namespace ola{
namespace client{
namespace gui{

class AuthWidget : public QWidget
{
    Q_OBJECT

public:
    AuthWidget(QWidget *parent = 0);

    void start();
};
}//namespace gui
}//namespace client
}//namespace ola
