# ola-client

OnLine Applications - client side 

```BASH
 ./configure -b debug -f debug -e ~/work/external_debug_x64/ -g "Visual Studio 16 2019" -P "-DSolidFrame_DIR=~/work/solidframe/build/debug" -P "-DQT5PREFIX_DIR:PATH=/c/data/qt/5.15.0/msvc2019_64/lib/cmake" -P "-DOLA_FRONT_URL:STRING=aws-dev.host" -A x64
 ./configure -b release -f release -e ~/work/external_release_x64/ -g "Visual Studio 16 2019" -P "-DSolidFrame_DIR=~/work/solidframe/build/release" -P "-DQT5PREFIX_DIR:PATH=/c/data/qt/5.15.0/msvc2019_64/lib/cmake" -P "-DOLA_FRONT_URL:STRING=front.myapps.space:443" -A x64
```
