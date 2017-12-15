#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <functional>
#include <iostream>
using boost::asio::ip::tcp;

using routine = std::function<void(tcp::iostream &)>;

namespace network {
    int port = 12345;
    std::string addr = "127.0.0.1";
};

int run_server(routine sr) {
    boost::asio::io_service ios;
    tcp::endpoint endpoint(tcp::v4(), network::port);
    tcp::acceptor acceptor(ios, endpoint);

    for (;;) {
        tcp::iostream conn;
        boost::system::error_code err;
        acceptor.accept(*conn.rdbuf(), err);
        if (!err) {
            sr(conn);
            conn.close();
            break;
        }
    }  
    return 0;
}

int run_client(routine cr) {
    tcp::iostream conn(network::addr, std::to_string(network::port));
    if (!conn) {
        std::cerr << "Can not connect to server!" << std::endl;
        return -1;
    }

    cr(conn);
    conn.close();
    return 1;
}

void send_big_int(std::vector<uint32_t> const& arr, 
                  tcp::iostream &conn) {
    int32_t sze = arr.size();
    conn << sze << '\n';
    for (size_t i = 0; i < sze; i++)
        conn << arr[i] << ' ';
    conn << '\n';
}

void receive_big_int(std::vector<uint32_t> &out,
                     tcp::iostream &conn) {
    int32_t sze; 
    conn >> sze;
    out.resize(sze);
    for (size_t i = 0; i < sze; i++)
        conn >> out[i];
}
