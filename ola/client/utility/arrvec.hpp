#pragma once

#include <vector>
#include <cassert>

namespace ola {
namespace client {
namespace utility {

template <size_t ArrSz, typename T>
class ArrVec{
    using VecT = std::vector<T>;
    size_t size_ = 0;
    T      arr_[ArrSz];
    VecT   vec_;
public:
    size_t size()const{
        return size_;
    }
    bool empty()const{
        return size_ == 0;
    }
    T& operator[](const size_t _i){
        assert(_i < size_);
        if(_i < ArrSz){
            return arr_[_i];
        }else{
            return vec_[_i - ArrSz];
        }
    }
    const T& operator[](const size_t _i)const{
        assert(_i < size_);
        if(_i < ArrSz){
            return arr_[_i];
        }else{
            return vec_[_i - ArrSz];
        }
    }
    
    template <typename... Args>
    void emplace_back(Args&&... _args){
        if(size_ < ArrSz){
            arr_[size_] = T(std::forward<Args>(_args)...);
        }else{
            vec_.emplace_back(std::forward<Args>(_args)...);
        }
        ++size_;
    }

    T& back(){
        return (*this)[size_ - 1];
    }
    const T& back()const{
        return (*this)[size_ - 1];
    }

    void clear(){
        size_ = 0;
        vec_.clear();
    }
};

} //namespace utility
} //namespace client
} //namespace ola