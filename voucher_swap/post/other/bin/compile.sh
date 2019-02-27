# bash script to compile bin
if [[ "$0" != "./compile.sh" ]]; then
    echo "Argument zero is not ./compile.sh"
    exit
fi
echo "Compiling..."
rm bin &> /dev/null
xcrun -sdk iphoneos clang -arch arm64 bin.c
mv a.out bin
echo "Done"
echo "Tarring..."
rm bin.tar.gz &> /dev/null
tar -cf bin.tar.gz bin
echo "Done"
echo "Cleaning up..."
rm bin &> /dev/null;
echo "Done"
