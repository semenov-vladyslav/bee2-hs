# bee2-hs
Haskell FFI bindings to [bee2](https://github.com/agievich/bee2) library.

## Build & Install
At this point the build process is not automated, so you'll have to make a few steps yourself.
First, build `bee2`. You will need `cmake`, `make` and `gcc` that is shipped with your `ghc`.
```
# get [bee2](https://github.com/agievich/bee2) library.
> git clone https://github.com/agievich/bee2
> cd bee2
# make build dir
> mkdir .ghc-bee2-build
> cd .ghc-bee2-build
# run cmake to create Makefile
> cmake -G "MSYS Makefiles" -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON ..
# build, make sure that proper gcc is used.
> make
```

Next, build `bee2-hs`. You'll need to provide `extra-include-dirs` and `extra-lib-dirs` to `cabal` or `stack`. I prefer using `cabal` sandboxes, it'll make `bee2-agda` build easier.
```
# create sandbox outside your project
# cd /path/to/bee2-hs/..
cabal sandbox init
# reuse sandbox inside bee2-hs
cd bee2-hs
cabal sandbox init --sandbox=../.cabal-sandbox
# build & install
cabal install --extra-include-dirs=../bee2/include --extra-lib-dirs=../bee2/.ghc-bee2-build/src
# this should work now
cabal exec -- bee2-exe
```

Now you should have `bee2-hs` library and `bee2-exe` executable installed within your sandbox.
