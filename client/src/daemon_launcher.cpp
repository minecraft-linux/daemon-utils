#include <daemon_utils/daemon_launcher.h>

#include <cstdio>
#include <unistd.h>
#include <sys/stat.h>
#include <FileUtil.h>
#include <log.h>

#ifndef __APPLE__
#include <sys/inotify.h>
#endif

using namespace daemon_utils;

void daemon_launcher::start() {
    std::string cwd = get_cwd();
    std::vector<std::string> args = get_arguments();
    if (!fork()) {
        setsid();
        chdir(cwd.c_str());
        char** argv = (char**) alloca(sizeof(char*) * (args.size() + 1));
        for (int i = 0; i < args.size(); i++)
            argv[i] = &args[i][0];
        argv[args.size()] = nullptr;
        Log::trace("DaemonLauncher", "Starting daemon: %s", argv[0]);
        int r = execv(argv[0], argv);
        printf("execv error %i\n", r);
    }
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
    start();
    inotify_event event;
    ssize_t n;
    while (true) {
        n = read(fd, &event, sizeof(event));
        if (n < 0)
            break;
        if (n != sizeof(event))
            throw std::runtime_error("Didn't read exactly the event size");
        if (event.wd == wd) {
            printf("File created: %s\n", event.name);
        }
    }
    close(fd);

    impl.open(service_path);
}
#endif
