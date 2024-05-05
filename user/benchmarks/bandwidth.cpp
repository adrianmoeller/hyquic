#include <iostream>
#include <cstring>
#include <chrono>
#include <hyquic_client.hpp>
#include <hyquic_server.hpp>
#include <stream_extension.hpp>

#define SEND_MSG_LEN 4096
#define RECV_MSG_LEN 4096 * 16
#define TOTAL_LEN 1 * 1024 * 1024 * 1024

using namespace hyquic;

int do_client_stream_ext(int argc, char *argv[])
{
    if (argc < 3)
        return -EINVAL;

    hyquic_client client(argv[2], atoi(argv[3]));

    stream_extension ext(client, false);
    client.register_extension(ext);

    client.connect_to_server();

    int err;
    uint64_t sent_bytes;
    stream_data send_msg(0, 0, buffer(SEND_MSG_LEN));

    auto start_time = std::chrono::steady_clock::now();

    send_msg.flags = QUIC_STREAM_FLAG_NEW;
    err = ext.send_msg(send_msg);
    if (err < 0)
        return err;
    sent_bytes += err;

    send_msg.flags = 0;
    while (true) {
        err = ext.send_msg(send_msg);
        if (err < 0)
            return err;
        sent_bytes += err;
        
        if (sent_bytes > TOTAL_LEN - SEND_MSG_LEN)
            break;
    }

    send_msg.flags = QUIC_STREAM_FLAG_FIN;
    err = ext.send_msg(send_msg);
    if (err < 0)
        return err;
    sent_bytes += err;

    std::optional<stream_data> recv_msg = ext.recv_msg(RECV_MSG_LEN, std::chrono::seconds(20));
    if (!recv_msg)
        return -1;

    auto elapsed = std::chrono::steady_clock::now() - start_time;
    double elapsed_sec = elapsed.count() / 1000 / 1000 / 1000;
    double total_len_kb = TOTAL_LEN / 1024;
    
    std::cout << "Bandwidth: " << total_len_kb / elapsed_sec << " KBytes/sec" << std::endl;

    client.close();

    return 0;
}

int do_client_no_ext(int argc, char *argv[])
{
    if (argc < 3)
        return -EINVAL;

    hyquic_client client(argv[2], atoi(argv[3]));
    client.connect_to_server();

    int err;
    uint64_t sent_bytes = 0;
    stream_data send_msg(0, 0, buffer(SEND_MSG_LEN));

    auto start_time = std::chrono::steady_clock::now();

    send_msg.flags = QUIC_STREAM_FLAG_NEW;
    err = client.send_msg(send_msg);
    if (err < 0)
        return err;
    sent_bytes += err;

    send_msg.flags = 0;
    while (true) {
        err = client.send_msg(send_msg);
        if (err < 0)
            return err;
        sent_bytes += err;
        
        if (!(sent_bytes % (SEND_MSG_LEN * 1024 * 4)))
			std::cout << "Sent " << sent_bytes / 1024 << "/" << TOTAL_LEN / 1024 << " KBytes." << std::endl;

        if (sent_bytes > TOTAL_LEN - SEND_MSG_LEN)
            break;
    }

    send_msg.flags = QUIC_STREAM_FLAG_FIN;
    err = client.send_msg(send_msg);
    if (err < 0)
        return err;
    sent_bytes += err;

    std::optional<stream_data> recv_msg = client.receive_msg(std::chrono::seconds(20));
    if (!recv_msg)
        return -1;

    auto elapsed = std::chrono::steady_clock::now() - start_time;
    double elapsed_sec = elapsed.count() / 1000 / 1000 / 1000;
    double total_len_kb = TOTAL_LEN / 1024;

    std::cout << "Bandwidth: " << total_len_kb / elapsed_sec << " KBytes/sec" << std::endl;

    client.close();

    return 0;
}

int do_client(int argc, char *argv[])
{
    if (argc < 5)
        return -EINVAL;

    if (!strcmp(argv[4], "ext"))
        return do_client_stream_ext(argc, argv);
    else
        return do_client_no_ext(argc, argv);
}

int do_server_stream_ext(int argc, char *argv[])
{
    if (argc < 5)
        return -EINVAL;

    hyquic_server server(argv[2], atoi(argv[3]));
    hyquic_server_connection connection = server.accept_connection();

    stream_extension ext(connection, true);
    connection.register_extension(ext);

    connection.connect_to_client(argv[4], argv[5]);

    uint64_t recv_bytes = 0;
    int err;

    while (true) {
        std::optional<stream_data> recv_msg = ext.recv_msg(RECV_MSG_LEN, std::chrono::seconds(20));
        if (!recv_msg)
            return -1;

        recv_bytes += recv_msg->buff.len;

        usleep(20);

        if (recv_msg->flags & QUIC_STREAM_FLAG_FIN)
            break;
    }

    stream_data send_msg(0, QUIC_STREAM_FLAG_FIN, buffer("Reception done."));
    err = ext.send_msg(send_msg);
    if (err < 0)
        return -1;

    sleep(1);
    connection.close();

    return 0;
}

int do_server_no_ext(int argc, char *argv[])
{
    if (argc < 5)
        return -EINVAL;

    hyquic_server server(argv[2], atoi(argv[3]));
    hyquic_server_connection connection = server.accept_connection();

    connection.connect_to_client(argv[4], argv[5]);

    uint64_t recv_bytes = 0;
    int err;

    while (true) {
        std::optional<stream_data> recv_msg = connection.receive_msg(std::chrono::seconds(20));
        if (!recv_msg)
            return -1;

        recv_bytes += recv_msg->buff.len;

        usleep(20);

        if (recv_msg->flags & QUIC_STREAM_FLAG_FIN)
            break;
    }

    stream_data send_msg(0, QUIC_STREAM_FLAG_FIN, buffer("Reception done."));
    err = connection.send_msg(send_msg);
    if (err < 0)
        return -1;

    sleep(1);
    connection.close();

    return 0;
}

int do_server(int argc, char *argv[])
{
    if (argc < 7)
        return -EINVAL;

    if (!strcmp(argv[7], "ext"))
        return do_server_stream_ext(argc, argv);
    else
        return do_server_no_ext(argc, argv);

    return 0;
}

int main(int argc, char *argv[])
{
    if (!strcmp(argv[1], "client"))
		return do_client(argc, argv);
    else
	    return do_server(argc, argv);
}