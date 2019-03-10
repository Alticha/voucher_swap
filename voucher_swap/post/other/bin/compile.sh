# shell script to compile bin
if [[ "$0" != "./compile.sh" ]]; then
    echo "Argument zero is not ./compile.sh"
    exit
fi
echo "Compiling..."
rm bin &> /dev/null
xcrun -sdk iphoneos clang -arch arm64 bin.c
mv a.out bin
echo "Done"
