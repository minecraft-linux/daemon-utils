#pragma once

#include <string>
#include <simpleipc/client/service_client_impl.h>

namespace daemon_utils {

class daemon_launcher {

protected:
    std::string service_path;

    void open(simpleipc::client::service_client_impl& impl);

public:
    daemon_launcher(std::string const& service_path) : service_path(service_path) {}

    virtual ~daemon_launcher() {}

    virtual void start();

    virtual std::vector<std::string> get_arguments() = 0;

    virtual std::string get_cwd() { return "/"; }

    std::unique_ptr<simpleipc::client::service_client_impl> open();

};

}