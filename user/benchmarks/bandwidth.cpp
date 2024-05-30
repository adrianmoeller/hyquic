#include <iostream>
#include <cstring>
#include <chrono>
#include <hyquic_client.hpp>
#include <hyquic_server.hpp>
#include <stream_extension.hpp>
#include <stream_injector.hpp>

using namespace hyquic;

#define SEND_MSG_LEN 4096
#define RECV_MSG_LEN 4096 * 16
#define TOTAL_LEN 1 * 1024 * 1024 * 1024

// #define SEND_PROGRESS_INTERVAL 8
// #define RECV_PROGRESS_INTERVAL 8

char snd_msg[SEND_MSG_LEN];
char rcv_msg[RECV_MSG_LEN];

static char default_address[] = "0.0.0.0";
static char default_port[] = "1234";

static struct {
	char *address = default_address;
	char *port = default_port;
    char *pkey = nullptr;
	char *cert = nullptr;
    bool server = false;
    char *mode = nullptr;
    uint32_t recv_buff_size = SOCK_RECV_BUFF_INIT_SIZE;
    time_t recv_timeout = SOCK_RECV_TIMEOUT;
    int ratio = 10;
    uint64_t send_msg_len = SEND_MSG_LEN;
    uint64_t total_len = TOTAL_LEN;
} options;

static inline void pr_final_bandwidth(double bandwidth, double sender_output)
{
#ifdef SEND_PROGRESS_INTERVAL
    std::cout << "Bandwidth: " << bandwidth << " KBytes/sec" << std::endl;
#else
    std::cout << bandwidth << "," << sender_output << std::endl;
#endif
}

static inline void pr_send_progress(uint64_t sent_bytes)
{
#ifdef SEND_PROGRESS_INTERVAL
    if (!(sent_bytes % (options.send_msg_len * 1024 * SEND_PROGRESS_INTERVAL)))
		std::cout << "Sent " << sent_bytes / 1024 << "/" << options.total_len / 1024 << " KBytes." << std::endl;
#endif
}

static inline void pr_recv_progress(uint64_t recvd_bytes)
{
#ifdef RECV_PROGRESS_INTERVAL
    if (!(recvd_bytes % (options.send_msg_len * 1024 * RECV_PROGRESS_INTERVAL)))
		std::cout << "Received " << recvd_bytes / 1024 << "/" << options.total_len / 1024 << " KBytes." << std::endl;
#endif
}

static int get_options(int argc, char *argv[])
{
    while (true) {
        switch (getopt(argc, argv, "sa:p:k:c:m:b:o:l:t:i:")) {
        case 's':
            options.server = true;
            continue;
        case 'a':
            options.address = optarg;
            continue;
        case 'p':
            options.port = optarg;
            continue;
        case 'k':
            options.pkey = optarg;
            continue;
        case 'c':
            options.cert = optarg;
            continue;
        case 'm':
            options.mode = optarg;
            continue;
        case 'b':
            options.recv_buff_size = atoi(optarg);
            continue;
        case 'o':
            options.recv_timeout = atoi(optarg);
            continue;
        case 'l':
            options.send_msg_len = atoll(optarg);
            continue;
        case 't':
            options.total_len = atoll(optarg);
            continue;
        case 'i':
            options.ratio = atoi(optarg);
            continue;
        case '?':
            std::cout << "Error: invalid argument." << std::endl;
            return -EINVAL;
        case -1:
            break;
        default:
            break;
        }

        break;
    }

    return 0;
}

static int do_client_stream_ext(int64_t &elapsed_us, int64_t & elapsed_sender_us, bool omit_ffs)
{
    hyquic_client client(options.address, atoi(options.port), options.recv_buff_size, options.recv_timeout);

    stream_extension ext(client, false, omit_ffs);
    client.register_extension(ext);

    client.connect_to_server(options.pkey);

    int err;
    uint64_t sent_bytes = 0;
    stream_data send_msg(0, 0, buffer(options.send_msg_len));

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
        
        if (sent_bytes > options.total_len - options.send_msg_len)
            break;
    }

    send_msg.flags = QUIC_STREAM_FLAG_FIN;
    err = ext.send_msg(send_msg);
    if (err < 0) {
        std::cout << "Error: send msg failed (" << err << ")." << std::endl;
        return err;
    }
    sent_bytes += err;

    auto elapsed_sender = std::chrono::steady_clock::now() - start_time;

    std::optional<stream_data> recv_msg = ext.recv_msg(RECV_MSG_LEN, std::chrono::seconds(20));
    if (!recv_msg) {
        std::cout << "Error: receive msg failed (timeout)." << std::endl;
        return -1;
    }

    auto elapsed = std::chrono::steady_clock::now() - start_time;
    elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
    elapsed_sender_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed_sender).count();

    client.close();

    return 0;
}

static int do_client_stream_ext_no_ffs(int64_t &elapsed_us, int64_t & elapsed_sender_us)
{
    return do_client_stream_ext(elapsed_us, elapsed_sender_us, true);
}

static int do_client_stream_ext(int64_t &elapsed_us, int64_t & elapsed_sender_us)
{
    return do_client_stream_ext(elapsed_us, elapsed_sender_us, false);
}

static int do_client_stream_inj(int64_t &elapsed_us, int64_t & elapsed_sender_us)
{
    hyquic_client client(options.address, atoi(options.port), options.recv_buff_size, options.recv_timeout);

    stream_injector inj(client);
    client.register_extension(inj);

    client.connect_to_server(options.pkey);

    int err;
    uint64_t sent_bytes = 0;
    uint32_t msg_counter = 0;
    stream_data send_msg(0, 0, buffer(options.send_msg_len));

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
        if ((msg_counter % 10) + 1 <= options.ratio) {
            err = inj.inject_msg(send_msg, sent_bytes);
        } else {
            err = client.send_msg(send_msg);
        }
        if (err < 0) {
            std::cout << "Error: send msg failed (" << err << ")." << std::endl;
            return err;
        }
        sent_bytes += err;
        msg_counter++;
        pr_send_progress(sent_bytes);
        
        if (sent_bytes > options.total_len - options.send_msg_len)
            break;
    }

    send_msg.flags = QUIC_STREAM_FLAG_FIN;
    err = client.send_msg(send_msg);
    if (err < 0) {
        std::cout << "Error: send msg failed (" << err << ")." << std::endl;
        return err;
    }
    sent_bytes += err;

    auto elapsed_sender = std::chrono::steady_clock::now() - start_time;

    std::optional<stream_data> recv_msg = client.receive_msg(std::chrono::seconds(20));
    if (!recv_msg) {
        std::cout << "Error: receive msg failed (timeout)." << std::endl;
        return -1;
    }

    auto elapsed = std::chrono::steady_clock::now() - start_time;
    elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
    elapsed_sender_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed_sender).count();

    client.close();

    return 0;
}

static int do_client_no_ext(int64_t &elapsed_us, int64_t & elapsed_sender_us)
{
    hyquic_client client(options.address, atoi(options.port), options.recv_buff_size, options.recv_timeout);
    client.connect_to_server(options.pkey);

    int err;
    uint64_t sent_bytes = 0;
    stream_data send_msg(0, 0, buffer(options.send_msg_len));

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

        if (sent_bytes > options.total_len - options.send_msg_len)
            break;
    }

    send_msg.flags = QUIC_STREAM_FLAG_FIN;
    err = client.send_msg(send_msg);
    if (err < 0) {
        std::cout << "Error: send msg failed (" << err << ")." << std::endl;
        return err;
    }
    sent_bytes += err;

    auto elapsed_sender = std::chrono::steady_clock::now() - start_time;

    std::optional<stream_data> recv_msg = client.receive_msg(std::chrono::seconds(20));
    if (!recv_msg) {
        std::cout << "Error: receive msg failed (timeout)." << std::endl;
        return -1;
    }

    auto elapsed = std::chrono::steady_clock::now() - start_time;
    elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
    elapsed_sender_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed_sender).count();

    client.close();

    return 0;
}

static int do_client_kern(int64_t &elapsed_us, int64_t & elapsed_sender_us)
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
    ra.sin_port = htons(atoi(options.port));
    inet_pton(AF_INET, options.address, &ra.sin_addr.s_addr);

	if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
		printf("Error: socket connect failed\n");
		return -1;
	}

	if (quic_client_handshake(sockfd, options.pkey, options.cert)) {
        printf("Error: handshake failed\n");
		return -1;
    }

	auto start_time = std::chrono::steady_clock::now();

	flag = QUIC_STREAM_FLAG_NEW;
	ret = quic_sendmsg(sockfd, snd_msg, options.send_msg_len, sid, flag);
	if (ret < 0) {
		printf("Error: send failed %d\n", ret);
		return ret;
	}
	sent_bytes += ret;
	flag = 0;
	while (true) {
		ret = quic_sendmsg(sockfd, snd_msg, options.send_msg_len, sid, flag);
		if (ret < 0) {
			printf("Error: send failed %d\n", ret);
			return ret;
		}
		sent_bytes += ret;
		pr_send_progress(sent_bytes);

		if (sent_bytes > options.total_len - options.send_msg_len)
			break;
	}
	flag = QUIC_STREAM_FLAG_FIN;
	ret = quic_sendmsg(sockfd, snd_msg, options.send_msg_len, sid, flag);
	if (ret < 0) {
		printf("Error: send failed %d\n", ret);
		return ret;
	}
	sent_bytes += ret;

    auto elapsed_sender = std::chrono::steady_clock::now() - start_time;

	memset(rcv_msg, 0, sizeof(rcv_msg));
	ret = quic_recvmsg(sockfd, rcv_msg, options.send_msg_len * 16, &sid, &flag);
	if (ret < 0) {
		printf("Error: receive failed %d\n", ret);
		return ret;
	}
	
    auto elapsed = std::chrono::steady_clock::now() - start_time;
    elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
    elapsed_sender_us = std::chrono::duration_cast<std::chrono::microseconds>(elapsed_sender).count();

	close(sockfd);
	return 0;
}

static int do_client()
{
    int64_t elapsed_us = 0;
    int64_t elapsed_sender_us = 0;
    int ret;

    if (!strcmp(options.mode, "ext_noffs"))
        ret = do_client_stream_ext_no_ffs(elapsed_us, elapsed_sender_us);
    else if (!strcmp(options.mode, "ext"))
        ret = do_client_stream_ext(elapsed_us, elapsed_sender_us);
    else if (!strcmp(options.mode, "inj"))
        ret = do_client_stream_inj(elapsed_us, elapsed_sender_us);
    else if (!strcmp(options.mode, "non"))
        ret = do_client_no_ext(elapsed_us, elapsed_sender_us);
    else if (!strcmp(options.mode, "kern"))
        ret = do_client_kern(elapsed_us, elapsed_sender_us);
    else {
        std::cout << "Error: unsupported client mode." << std::endl;
        return -EINVAL;
    }

    double total_len_kb = options.total_len / 1024;
    pr_final_bandwidth(total_len_kb * 1000 * 1000 / elapsed_us, total_len_kb * 1000 * 1000 / elapsed_sender_us);

    return ret;
}

static int do_server_stream_ext(bool omit_ffs)
{
    hyquic_server server(options.address, atoi(options.port));

    while (true) {
        hyquic_server_connection connection = server.accept_connection(options.recv_buff_size, options.recv_timeout);

        stream_extension ext(connection, true, omit_ffs);
        connection.register_extension(ext);

        connection.connect_to_client(options.pkey, options.cert);

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

static int do_server_stream_ext_no_ffs()
{
    return do_server_stream_ext(true);
}

static int do_server_stream_ext()
{
    return do_server_stream_ext(false);
}

static int do_server_no_ext()
{
    hyquic_server server(options.address, atoi(options.port));

    while (true) {
        hyquic_server_connection connection = server.accept_connection(options.recv_buff_size, options.recv_timeout);

        connection.connect_to_client(options.pkey, options.cert);

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

static int do_server_kern()
{
	struct quic_transport_param param = {};
	struct sockaddr_storage ra = {};
	struct sockaddr_in la = {};
	uint32_t flag = 0, addrlen;
	uint64_t recv_bytes = 0, sid = 0;
	int ret, sockfd, listenfd;

	la.sin_family = AF_INET;
	la.sin_port = htons(atoi(options.port));
	inet_pton(AF_INET, options.address, &la.sin_addr.s_addr);
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

        if (quic_server_handshake(sockfd, options.pkey, options.cert)) {
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

static int do_server()
{
    if (!strcmp(options.mode, "ext_noffs"))
        return do_server_stream_ext_no_ffs();
    if (!strcmp(options.mode, "ext"))
        return do_server_stream_ext();
    else if (!strcmp(options.mode, "non"))
        return do_server_no_ext();
    else if (!strcmp(options.mode, "kern"))
        return do_server_kern();

    std::cout << "Error: unsupported server mode." << std::endl;
    return -EINVAL;
}

int main(int argc, char *argv[])
{
    if (get_options(argc, argv))
        return 1;

    if (options.server) {
	    return do_server();
    } else {
		return do_client();
    }
}