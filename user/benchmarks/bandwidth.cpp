#include <iostream>
#include <cstring>
#include <chrono>
#include <hyquic_client.hpp>
#include <hyquic_server.hpp>
#include <stream_extension.hpp>

using namespace hyquic;

#define SEND_MSG_LEN 4096
#define RECV_MSG_LEN 4096 * 16
#define TOTAL_LEN 1 * 1024 * 1024 * 1024
#define PROGRESS_INTERVAL 8

char snd_msg[SEND_MSG_LEN];
char rcv_msg[RECV_MSG_LEN];

int do_client_stream_ext(int argc, char *argv[])
{
    if (argc < 3) {
        std::cout << "Error: invalid argument count." << std::endl;
        return -EINVAL;
    }

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
    if (err < 0) {
        std::cout << "Error: send msg failed (" << err << ")." << std::endl;
        return err;
    }
    sent_bytes += err;

    send_msg.flags = 0;
    while (true) {
        err = ext.send_msg(send_msg);
        if (err < 0) {
            std::cout << "Error: send msg failed (" << err << ")." << std::endl;
            return err;
        }
        sent_bytes += err;

        if (!(sent_bytes % (SEND_MSG_LEN * 1024 * PROGRESS_INTERVAL)))
			std::cout << "Sent " << sent_bytes / 1024 << "/" << TOTAL_LEN / 1024 << " KBytes." << std::endl;
        
        if (sent_bytes > TOTAL_LEN - SEND_MSG_LEN)
            break;
    }

    send_msg.flags = QUIC_STREAM_FLAG_FIN;
    err = ext.send_msg(send_msg);
    if (err < 0) {
        std::cout << "Error: send msg failed (" << err << ")." << std::endl;
        return err;
    }
    sent_bytes += err;

    std::optional<stream_data> recv_msg = ext.recv_msg(RECV_MSG_LEN, std::chrono::seconds(20));
    if (!recv_msg) {
        std::cout << "Error: receive msg failed (timeout)." << std::endl;
        return -1;
    }

    auto elapsed = std::chrono::steady_clock::now() - start_time;
    double elapsed_sec = elapsed.count() / 1000 / 1000 / 1000;
    double total_len_kb = TOTAL_LEN / 1024;
    
    std::cout << "Bandwidth: " << total_len_kb / elapsed_sec << " KBytes/sec" << std::endl;

    client.close();

    return 0;
}

int do_client_no_ext(int argc, char *argv[])
{
    if (argc < 3) {
        std::cout << "Error: invalid argument count." << std::endl;
        return -EINVAL;
    }

    hyquic_client client(argv[2], atoi(argv[3]));
    client.connect_to_server();

    int err;
    uint64_t sent_bytes = 0;
    stream_data send_msg(0, 0, buffer(SEND_MSG_LEN));

    auto start_time = std::chrono::steady_clock::now();

    send_msg.flags = QUIC_STREAM_FLAG_NEW;
    err = client.send_msg(send_msg);
    if (err < 0) {
        std::cout << "Error: send msg failed (" << err << ")." << std::endl;
        return err;
    }
    sent_bytes += err;

    send_msg.flags = 0;
    while (true) {
        err = client.send_msg(send_msg);
        if (err < 0) {
            std::cout << "Error: send msg failed (" << err << ")." << std::endl;
            return err;
        }
        sent_bytes += err;
        
        if (!(sent_bytes % (SEND_MSG_LEN * 1024 * PROGRESS_INTERVAL)))
			std::cout << "Sent " << sent_bytes / 1024 << "/" << TOTAL_LEN / 1024 << " KBytes." << std::endl;

        if (sent_bytes > TOTAL_LEN - SEND_MSG_LEN)
            break;
    }

    send_msg.flags = QUIC_STREAM_FLAG_FIN;
    err = client.send_msg(send_msg);
    if (err < 0) {
        std::cout << "Error: send msg failed (" << err << ")." << std::endl;
        return err;
    }
    sent_bytes += err;

    std::optional<stream_data> recv_msg = client.receive_msg(std::chrono::seconds(20));
    if (!recv_msg) {
        std::cout << "Error: receive msg failed (timeout)." << std::endl;
        return -1;
    }

    auto elapsed = std::chrono::steady_clock::now() - start_time;
    double elapsed_sec = elapsed.count() / 1000 / 1000 / 1000;
    double total_len_kb = TOTAL_LEN / 1024;

    std::cout << "Bandwidth: " << total_len_kb / elapsed_sec << " KBytes/sec" << std::endl;

    client.close();

    return 0;
}

int do_client_kern(int argc, char *argv[])
{
	struct sockaddr_in ra = {};
	uint64_t sent_bytes = 0, sid = 0;
	time_t start, end;
	int ret, sockfd;
	uint32_t flag;

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		printf("socket create failed\n");
		return -1;
	}

    ra.sin_family = AF_INET;
    ra.sin_port = htons(atoi(argv[3]));
    inet_pton(AF_INET, argv[2], &ra.sin_addr.s_addr);

	if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
		printf("socket connect failed\n");
		return -1;
	}

	if (quic_client_handshake(sockfd, nullptr, nullptr)) {
        printf("handshake failed\n");
		return -1;
    }

	auto start_time = std::chrono::steady_clock::now();

	flag = QUIC_STREAM_FLAG_NEW;
	ret = quic_sendmsg(sockfd, snd_msg, SEND_MSG_LEN, sid, flag);
	if (ret == -1) {
		printf("send %d\n", ret);
		return -1;
	}
	sent_bytes += ret;
	flag = 0;
	while (1) {
		ret = quic_sendmsg(sockfd, snd_msg, SEND_MSG_LEN, sid, flag);
		if (ret == -1) {
			printf("send %d\n", ret);
			return -1;
		}
		sent_bytes += ret;
		if (!(sent_bytes % (SEND_MSG_LEN * 1024 * PROGRESS_INTERVAL)))
			std::cout << "Sent " << sent_bytes / 1024 << "/" << TOTAL_LEN / 1024 << " KBytes." << std::endl;
		if (sent_bytes > TOTAL_LEN - SEND_MSG_LEN)
			break;
	}
	flag = QUIC_STREAM_FLAG_FIN;
	ret = quic_sendmsg(sockfd, snd_msg, SEND_MSG_LEN, sid, flag);
	if (ret == -1) {
		printf("send %d\n", ret);
		return -1;
	}
	sent_bytes += ret;

	memset(rcv_msg, 0, sizeof(rcv_msg));
	ret = quic_recvmsg(sockfd, rcv_msg, SEND_MSG_LEN * 16, &sid, &flag);
	if (ret == -1) {
		printf("recv error %d\n", ret);
		return 1;
	}
	
    auto elapsed = std::chrono::steady_clock::now() - start_time;
    double elapsed_sec = elapsed.count() / 1000 / 1000 / 1000;
    double total_len_kb = TOTAL_LEN / 1024;

    std::cout << "Bandwidth: " << total_len_kb / elapsed_sec << " KBytes/sec" << std::endl;

	close(sockfd);
	return 0;
}

int do_client(int argc, char *argv[])
{
    if (argc < 5) {
        std::cout << "Error: invalid argument count." << std::endl;
        return -EINVAL;
    }

    if (!strcmp(argv[4], "ext"))
        return do_client_stream_ext(argc, argv);
    else if (!strcmp(argv[4], "non"))
        return do_client_no_ext(argc, argv);
    else
        return do_client_kern(argc, argv);
}

int do_server_stream_ext(int argc, char *argv[])
{
    if (argc < 5) {
        std::cout << "Error: invalid argument count." << std::endl;
        return -EINVAL;
    }

    hyquic_server server(argv[2], atoi(argv[3]));
    hyquic_server_connection connection = server.accept_connection();

    stream_extension ext(connection, true);
    connection.register_extension(ext);

    connection.connect_to_client(argv[4], argv[5]);

    uint64_t recv_bytes = 0;
    int err;

    while (true) {
        std::optional<stream_data> recv_msg = ext.recv_msg(RECV_MSG_LEN, std::chrono::seconds(20));
        if (!recv_msg) {
            std::cout << "Error: receive msg failed (timeout)." << std::endl;
            return -1;
        }

        recv_bytes += recv_msg->buff.len;

        if (!(recv_bytes % (SEND_MSG_LEN * 1024 * PROGRESS_INTERVAL)))
			std::cout << "Received " << recv_bytes / 1024 << "/" << TOTAL_LEN / 1024 << " KBytes." << std::endl;

        // usleep(20);

        if (recv_msg->flags & QUIC_STREAM_FLAG_FIN)
            break;
    }

    stream_data send_msg(0, QUIC_STREAM_FLAG_FIN, buffer("Reception done."));
    err = ext.send_msg(send_msg);
    if (err < 0) {
        std::cout << "Error: send msg failed (" << err << ")." << std::endl;
        return err;
    }

    sleep(1);
    connection.close();

    return 0;
}

int do_server_no_ext(int argc, char *argv[])
{
    if (argc < 5) {
        std::cout << "Error: invalid argument count." << std::endl;
        return -EINVAL;
    }

    hyquic_server server(argv[2], atoi(argv[3]));
    hyquic_server_connection connection = server.accept_connection();

    connection.connect_to_client(argv[4], argv[5]);

    uint64_t recv_bytes = 0;
    int err;

    while (true) {
        std::optional<stream_data> recv_msg = connection.receive_msg(std::chrono::seconds(20));
        if (!recv_msg) {
            std::cout << "Error: receive msg failed (timeout)." << std::endl;
            return -1;
        }

        recv_bytes += recv_msg->buff.len;

        if (!(recv_bytes % (SEND_MSG_LEN * 1024 * PROGRESS_INTERVAL)))
			std::cout << "Received " << recv_bytes / 1024 << "/" << TOTAL_LEN / 1024 << " KBytes." << std::endl;

        // usleep(20);

        if (recv_msg->flags & QUIC_STREAM_FLAG_FIN)
            break;
    }

    stream_data send_msg(0, QUIC_STREAM_FLAG_FIN, buffer("Reception done."));
    err = connection.send_msg(send_msg);
    if (err < 0) {
        std::cout << "Error: send msg failed (" << err << ")." << std::endl;
        return err;
    }

    sleep(1);
    connection.close();

    return 0;
}

int do_server_kern(int argc, char *argv[])
{
	struct quic_transport_param param = {};
	struct sockaddr_storage ra = {};
	struct sockaddr_in la = {};
	uint32_t flag = 0, addrlen;
	uint64_t recv_bytes = 0,  sid = 0;
	int ret, sockfd, listenfd;

	la.sin_family = AF_INET;
	la.sin_port = htons(atoi(argv[3]));
	inet_pton(AF_INET, argv[2], &la.sin_addr.s_addr);
	listenfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (listenfd < 0) {
		printf("socket create failed\n");
		return -1;
	}
	if (bind(listenfd, (struct sockaddr *)&la, sizeof(la))) {
		printf("socket bind failed\n");
		return -1;
	}

	if (listen(listenfd, 1)) {
		printf("socket listen failed\n");
		return -1;
	}

	addrlen = sizeof(ra);
	sockfd = accept(listenfd, (struct sockaddr *)&ra, &addrlen);
	if (sockfd < 0) {
		printf("socket accept failed %d\n", sockfd);
		return -1;
	}

	if (quic_server_handshake(sockfd, argv[4], argv[5])) {
        printf("handshake failed\n");
		return -1;
    }

	while (1) {
		ret = quic_recvmsg(sockfd, &rcv_msg, RECV_MSG_LEN, &sid, &flag);
		if (ret == -1) {
			printf("recv error %d\n", ret);
			return 1;
		}
		recv_bytes += ret;

        usleep(20);

        if (!(recv_bytes % (SEND_MSG_LEN * 1024 * PROGRESS_INTERVAL)))
			std::cout << "Received " << recv_bytes / 1024 << "/" << TOTAL_LEN / 1024 << " KBytes." << std::endl;

		if (flag & QUIC_STREAM_FLAG_FIN)
			break;
	}

	flag = QUIC_STREAM_FLAG_FIN;
	strcpy(snd_msg, "Reception done.");
	ret = quic_sendmsg(sockfd, snd_msg, strlen(snd_msg), sid, flag);
	if (ret == -1) {
		printf("send %d\n", ret);
		return -1;
	}
	sleep(1);
	close(sockfd);

	return 0;
}

int do_server(int argc, char *argv[])
{
    if (argc < 7) {
        std::cout << "Error: invalid argument count." << std::endl;
        return -EINVAL;
    }

    if (!strcmp(argv[7], "ext"))
        return do_server_stream_ext(argc, argv);
    else if (!strcmp(argv[7], "non"))
        return do_server_no_ext(argc, argv);
    else
        return do_server_kern(argc, argv);

    return 0;
}

int main(int argc, char *argv[])
{
    if (!strcmp(argv[1], "client"))
		return do_client(argc, argv);
    else
	    return do_server(argc, argv);
}