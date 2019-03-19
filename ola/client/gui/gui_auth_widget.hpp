#pragma once

#include "solid/system/pimpl.hpp"
#include <QWidget>
#include <string>

namespace ola {
namespace client {
namespace gui {

class AuthWidget : public QWidget {
    Q_OBJECT
    struct Data;
    solid::PimplT<Data> pimpl_;

public:
    AuthWidget(QWidget* parent = 0);
    ~AuthWidget();

    void setUser(const std::string& _user);

    void start();
};
} //namespace gui
} //namespace client
} //namespace ola
