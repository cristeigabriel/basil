#include "../basil.hh"
#include <iostream>
#include <stdexcept>

using namespace basil;
int main() {
    try {
        // capture contents of process named "csgo.exe" in the process list
        basil::ctx obj("csgo.exe");

        // print name and pid
        std::cout << "name: " << obj.get_name() << " pid: " << obj.get_pid().value() << '\n';

        // store all modules
        obj.capture_all_modules();

        // retrieve "client.dll", we assume it's present by retrieving value directly
        auto client = obj.get_module("client.dll").value();

        // print start as an address and size, in hex
        std::cout << std::hex << "start: " << (uintptr_t)(client.start_) << " size: " << client.size_ << '\n';

        // auto state = obj.write_module_memory("fastprox.dll", 0xB5210, 0x0);
        // if (state.first) {
        //     std::cout << "succesfully wrote at said address.\n";
        // }

        // read first memory page from client.dll, assume page is readable and that we won't have a partial copy by retrieving
        // value directly
        auto page = obj.read_module_memory<detail::page>("client.dll", 0x0).value();

        // print first page
        for (auto b : page.first) {
            std::cout << b;
        }

        // find pointer to local player position in entity list
        constexpr std::array local_sig = {0x83, 0x3D, -1, -1, -1, -1, -1, 0x75, 0x68, 0x8B, 0x0D, -1, -1, -1, -1, 0x8B, 0x01};
        auto local                     = obj.pattern_scan_module("client.dll", local_sig);
        if (local.has_value()) {
            std::cout << '\n'
                      << "local: " << std::hex << local.value() + 2 << '\n';
        }
    } catch (const std::exception& err) {
        // print and flush buffers
        std::cout << err.what() << std::endl;
        std::exit(EXIT_FAILURE);
    }

    return 0;
}