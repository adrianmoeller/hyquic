#include <iostream>
#include <cstring>
#include <stream_extension.hpp>

void do_client(int argc, char *argv[])
{
    // TODO
}

void do_server(int argc, char *argv[])
{
    // TODO
}

int main(int argc, char *argv[])
{
    if (!strcmp(argv[1], "client"))
		do_client(argc, argv);
    else
	    do_server(argc, argv);
}