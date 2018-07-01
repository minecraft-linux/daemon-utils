#include <daemon_utils/daemon_launcher.h>

#include <cstdio>
#include <unistd.h>
#include <sys/stat.h>
#include <FileUtil.h>
#include <log.h>

#ifndef __APPLE__
#include <sys/inotify.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <simpleipc/common/io_handler.h>
#include <future>
#endif

using namespace daemon_utils;

pid_t daemon_launcher::start() {
    std::string cwd = get_cwd();
    std::vector<std::string> args = get_arguments();
    pid_t ret;
    if (!(ret = fork())) {
        setsid();
        chdir(cwd.c_str());
        char** argv = (char**) alloca(sizeof(char*) * (args.size() + 1));
        for (int i = 0; i < args.size(); i++)
            argv[i] = &args[i][0];
        argv[args.size()] = nullptr;
        Log::trace("DaemonLauncher", "Starting daemon: %s", argv[0]);
        int r = execv(argv[0], argv);
        Log::error("DaemonLauncher", "execv error %i\n", r);
        _exit(1);
    }
    if (ret < 0)
        throw std::runtime_error("fork failed");
    return ret;
}

#ifndef __APPLE__
void daemon_launcher::open(simpleipc::client::service_client_impl& impl) {
    struct stat s;
    stat(service_path.c_str(), &s);
    if (S_ISSOCK(s.st_mode)) {
        // try open
        try {
            impl.open(service_path);
            return;
        } catch (std::exception& e) {
            // open failed
            Log::info("DaemonLauncher", "Daemon file exists, but we could not open it (%s); "
                    "starting the service anyways", e.what());
        }
    }
    // Start the service and wait for the service file to show up
    int fd = inotify_init();
    if (fd < 0)
        throw std::runtime_error("inotify_init failed");
    int wd = inotify_add_watch(fd, FileUtil::getParent(service_path).c_str(), IN_CREATE);
    if (wd < 0)
        throw std::runtime_error("inotify_add_watch failed");

    // Try to open the file again, in case the service was stated in the meanwhile
    stat(service_path.c_str(), &s);
    if (S_ISSOCK(s.st_mode)) {
        try {
            impl.open(service_path);
            close(fd);
            return;
        } catch (std::exception& e) {
        }
    }

    pid_t proc = start();

    std::promise<void> stop_promise;
    auto stop_future = stop_promise.get_future();

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    int sfd = signalfd(-1, &mask, SFD_NONBLOCK);
    simpleipc::io_handler::get_instance().add_socket(sfd, [proc, &stop_promise](int fd) {
        int status;
        if (waitpid(proc, &status, WNOHANG) == -1)
            return;
        stop_promise.set_value();
    }, [&stop_promise](int fd) {
        stop_promise.set_value();
    });
    simpleipc::io_handler::get_instance().add_socket(fd, [wd, &stop_promise](int fd) {
        unsigned int av;
        ioctl(fd, FIONREAD, &av);
        bool bufs = av < 1024 * 16;
        char* buf = (char*) (bufs ? alloca(av) : malloc(av));
        int n = read(fd, buf, av);
        if (n != av) {
            Log::warn("DaemonLauncher", "Didn't read exactly the event size");
            if (!bufs)
                free(buf);
            return;
        }
        size_t o = 0;
        while (o < av) {
            inotify_event& event = *((inotify_event*) &buf[o]);
            if (event.wd == wd) {
                if (strncmp(event.name, "service", event.len) == 0)
                    stop_promise.set_value();
            }
            o += sizeof(inotify_event) + event.len;
        }
        if (!bufs)
            free(buf);
    }, [&stop_promise](int fd) {
        stop_promise.set_value();
    });

    stop_future.wait_for(std::chrono::seconds(10));
    simpleipc::io_handler::get_instance().remove_socket(sfd);
    simpleipc::io_handler::get_instance().remove_socket(fd);
    close(sfd);
    close(fd);

    impl.open(service_path);
}
#endif
