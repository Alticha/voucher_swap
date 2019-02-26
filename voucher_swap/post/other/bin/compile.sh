# bash script to compile bin
# hope you're in the right directory
rm bin &> /dev/null; rm bin.tar.gz &> /dev/null; xcrun -sdk iphoneos clang -arch arm64 bin.c; mv a.out bin; ldid2 -Sent.entitlements bin; tar -cf bin.tar.gz bin; rm bin &> /dev/null;
