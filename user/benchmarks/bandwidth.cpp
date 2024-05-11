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

// #define SEND_PROGRESS_INTERVAL 8
// #define RECV_PROGRESS_INTERVAL 8

char snd_msg[SEND_MSG_LEN];
char rcv_msg[RECV_MSG_LEN];

static inline void pr_final_bandwidth(double bandwidth)
{
#ifdef SEND_PROGRESS_INTERVAL
    std::cout << "Bandwidth: " << bandwidth << " KBytes/sec" << std::endl;
#else
    std::cout << bandwidth << std::endl;
#endif
}

static inline void pr_send_progress(uint64_t sent_bytes)
{
#ifdef SEND_PROGRESS_INTERVAL
    if (!(sent_bytes % (SEND_MSG_LEN * 1024 * SEND_PROGRESS_INTERVAL)))
		std::cout << "Sent " << sent_bytes / 1024 << "/" << TOTAL_LEN / 1024 << " KBytes." << std::endl;
#endif
}

static inline void pr_recv_progress(uint64_t recvd_bytes)
{
#ifdef RECV_PROGRESS_INTERVAL
    if (!(recvd_bytes % (SEND_MSG_LEN * 1024 * RECV_PROGRESS_INTERVAL)))
		std::cout << "Received " << recvd_bytes / 1024 << "/" << TOTAL_LEN / 1024 << " KBytes." << std::endl;
#endif
}

int do_client_stream_ext(int argc, char *argv[], int64_t &elapsed_us, bool omit_ffs)
{
    if (argc < 3) {
        std::cout << "Error: invalid argument count." << std::endl;
        return -EINVAL;
    }

    hyquic_client client(argv[2], atoi(argv[3]));

    stream_extension ext(client, false, omit_ffs);
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
        pr_send_progress(sent_bytes);
        
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
    elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();

    client.close();

    return 0;
}

int do_client_stream_ext_no_ffs(int argc, char *argv[], int64_t &elapsed_us)
{
    return do_client_stream_ext(argc, argv, elapsed_us, true);
}

int do_client_stream_ext(int argc, char *argv[], int64_t &elapsed_us)
{
    return do_client_stream_ext(argc, argv, elapsed_us, false);
}

int do_client_no_ext(int argc, char *argv[], int64_t &elapsed_us)
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
        pr_send_progress(sent_bytes);

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
    elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();

    client.close();

    return 0;
}

int do_client_kern(int argc, char *argv[], int64_t &elapsed_us)
{
	struct sockaddr_in ra = {};
	uint64_t sent_bytes = 0, sid = 0;
	time_t start, end;
	int ret, sockfd;
	uint32_t flag;

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		printf("Error: socket create failed\n");
		return sockfd;
	}

    ra.sin_family = AF_INET;
    ra.sin_port = htons(atoi(argv[3]));
    inet_pton(AF_INET, argv[2], &ra.sin_addr.s_addr);

	if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
		printf("Error: socket connect failed\n");
		return -1;
	}

	if (quic_client_handshake(sockfd, nullptr, nullptr)) {
        printf("Error: handshake failed\n");
		return -1;
    }

	auto start_time = std::chrono::steady_clock::now();

	flag = QUIC_STREAM_FLAG_NEW;
	ret = quic_sendmsg(sockfd, snd_msg, SEND_MSG_LEN, sid, flag);
	if (ret < 0) {
		printf("Error: send failed %d\n", ret);
		return ret;
	}
	sent_bytes += ret;
	flag = 0;
	while (true) {
		ret = quic_sendmsg(sockfd, snd_msg, SEND_MSG_LEN, sid, flag);
		if (ret < 0) {
			printf("Error: send failed %d\n", ret);
			return ret;
		}
		sent_bytes += ret;
		pr_send_progress(sent_bytes);

		if (sent_bytes > TOTAL_LEN - SEND_MSG_LEN)
			break;
	}
	flag = QUIC_STREAM_FLAG_FIN;
	ret = quic_sendmsg(sockfd, snd_msg, SEND_MSG_LEN, sid, flag);
	if (ret < 0) {
		printf("Error: send failed %d\n", ret);
		return ret;
	}
	sent_bytes += ret;

	memset(rcv_msg, 0, sizeof(rcv_msg));
	ret = quic_recvmsg(sockfd, rcv_msg, SEND_MSG_LEN * 16, &sid, &flag);
	if (ret < 0) {
		printf("Error: receive failed %d\n", ret);
		return ret;
	}
	
    auto elapsed = std::chrono::steady_clock::now() - start_time;
    elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();

	close(sockfd);
	return 0;
}

int do_client(int argc, char *argv[])
{
    if (argc < 5) {
        std::cout << "Error: invalid argument count." << std::endl;
        return -EINVAL;
    }

    int64_t elapsed_us = 0;
    int ret;

    if (!strcmp(argv[4], "ext_noffs"))
        ret = do_client_stream_ext_no_ffs(argc, argv, elapsed_us);
    else if (!strcmp(argv[4], "ext"))
        ret = do_client_stream_ext(argc, argv, elapsed_us);
    else if (!strcmp(argv[4], "non"))
        ret = do_client_no_ext(argc, argv, elapsed_us);
    else if (!strcmp(argv[4], "kern"))
        ret = do_client_kern(argc, argv, elapsed_us);
    else {
        std::cout << "Error: unsupported client mode." << std::endl;
        return -EINVAL;
    }

    double total_len_kb = TOTAL_LEN / 1024;
    pr_final_bandwidth(total_len_kb * 1000 * 1000 / elapsed_us);

    return ret;
}

int do_server_stream_ext(int argc, char *argv[], bool omit_ffs)
{
    if (argc < 5) {
        std::cout << "Error: invalid argument count." << std::endl;
        return -EINVAL;
    }

    hyquic_server server(argv[2], atoi(argv[3]));

    while (true) {
        hyquic_server_connection connection = server.accept_connection();

        stream_extension ext(connection, true, omit_ffs);
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
            pr_recv_progress(recv_bytes);

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
    }

    return 0;
}

int do_server_stream_ext_no_ffs(int argc, char *argv[])
{
    return do_server_stream_ext(argc, argv, true);
}

int do_server_stream_ext(int argc, char *argv[])
{
    return do_server_stream_ext(argc, argv, false);
}

int do_server_no_ext(int argc, char *argv[])
{
    if (argc < 5) {
        std::cout << "Error: invalid argument count." << std::endl;
        return -EINVAL;
    }

    hyquic_server server(argv[2], atoi(argv[3]));

    while (true) {
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
            pr_recv_progress(recv_bytes);

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
    }

    return 0;
}

int do_server_kern(int argc, char *argv[])
{
	struct quic_transport_param param = {};
	struct sockaddr_storage ra = {};
	struct sockaddr_in la = {};
	uint32_t flag = 0, addrlen;
	uint64_t recv_bytes = 0, sid = 0;
	int ret, sockfd, listenfd;

	la.sin_family = AF_INET;
	la.sin_port = htons(atoi(argv[3]));
	inet_pton(AF_INET, argv[2], &la.sin_addr.s_addr);
	listenfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (listenfd < 0) {
		printf("Error: socket create failed\n");
		return listenfd;
	}
	if (bind(listenfd, (struct sockaddr *)&la, sizeof(la))) {
		printf("Error: socket bind failed\n");
		return -1;
	}

	if (listen(listenfd, 1)) {
		printf("Error: socket listen failed\n");
		return -1;
	}

    while (true) {
        addrlen = sizeof(ra);
        sockfd = accept(listenfd, (struct sockaddr *)&ra, &addrlen);
        if (sockfd < 0) {
            printf("Error: socket accept failed %d\n", sockfd);
            return -1;
        }

        if (quic_server_handshake(sockfd, argv[4], argv[5])) {
            printf("Error: handshake failed\n");
            return -1;
        }

        while (true) {
            ret = quic_recvmsg(sockfd, &rcv_msg, RECV_MSG_LEN, &sid, &flag);
            if (ret < 0) {
                printf("Error: receive failed %d\n", ret);
                return ret;
            }
            recv_bytes += ret;

            // usleep(20);
            
            pr_recv_progress(recv_bytes);

            if (flag & QUIC_STREAM_FLAG_FIN)
                break;
        }

        flag = QUIC_STREAM_FLAG_FIN;
        strcpy(snd_msg, "Reception done.");
        ret = quic_sendmsg(sockfd, snd_msg, strlen(snd_msg), sid, flag);
        if (ret < 0) {
            printf("Error: send failed %d\n", ret);
            return ret;
        }
        sleep(1);
        close(sockfd);
    }

	return 0;
}

int do_server(int argc, char *argv[])
{
    if (argc < 7) {
        std::cout << "Error: invalid argument count." << std::endl;
        return -EINVAL;
    }

    if (!strcmp(argv[6], "ext_noffs"))
        return do_server_stream_ext_no_ffs(argc, argv);
    if (!strcmp(argv[6], "ext"))
        return do_server_stream_ext(argc, argv);
    else if (!strcmp(argv[6], "non"))
        return do_server_no_ext(argc, argv);
    else if (!strcmp(argv[6], "kern"))
        return do_server_kern(argc, argv);

    std::cout << "Error: unsupported server mode." << std::endl;
    return -EINVAL;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cout << "Error: invalid argument count." << std::endl;
        return -EINVAL;
    }

    if (!strcmp(argv[1], "client")) {
		return do_client(argc, argv);
    } else {
	    return do_server(argc, argv);
    }
}