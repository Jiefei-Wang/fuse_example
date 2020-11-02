fuse_test_code.o: fuse_test_code.cpp
	g++ -std=c++11 -g -Wall `pkg-config fuse --cflags` -c fuse_test_code.cpp -O0

test: fuse_test_code.o
	g++ -std=c++11 -g -o test fuse_test_code.o `pkg-config fuse --libs` -O0

