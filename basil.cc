#include "basil.hh"
#include <TlHelp32.h>
#include <stdexcept>

using namespace basil;
ctx::ctx(std::string&& name) {
    // save some time with obvious cases
    if (!name.ends_with(".exe")) {
        throw std::runtime_error("Extension not supported for process context.");
        return;
    }
    if (name.empty()) {
        throw std::runtime_error("Empty name.");
        return;
    }

    // assign name
    this->name_            = std::move(name);
    const size_t name_hash = detail::hasher<>::get(this->name_.c_str(), this->name_.size());

    // get local snapshot to use in process iteration
    HANDLE local_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, detail::local_pid);
    if (local_snapshot == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Invalid handle value on local snapshot.");
        return;
    }

    // buffer that stores information of the current process in the iteration
    PROCESSENTRY32 buffer = PROCESSENTRY32 {.dwSize = sizeof(PROCESSENTRY32)};
    for (bool copied = Process32First(local_snapshot, &buffer); copied; copied = Process32Next(local_snapshot, &buffer)) {
        const size_t current_hash = detail::hasher<>::get(buffer.szExeFile, strlen(buffer.szExeFile));

        if (name_hash == current_hash) {
            this->pid_ = buffer.th32ProcessID;
        }
    }

    // local snapshot not needed anymore
    CloseHandle(local_snapshot);

    // check for PID
    if (!this->pid_.has_value()) {
        throw std::runtime_error("Failed finding process " + this->name_ + " in process list.");
        return;
    } else {
        if (this->pid_.value() == 0) {
            throw std::runtime_error("Process " + this->name_ + "'s PID is 0. Exiting.");
            return;
        }
    }

    // capture target process handle
    this->handle_ = OpenProcess(PROCESS_ALL_ACCESS, false, this->pid_.value());

    // check for handle
    if (!this->handle_.has_value()) {
        throw std::runtime_error("Failed opening handle to " + this->name_ + " in process list.");
        return;
    } else {
        if (this->handle_.value() == nullptr) {
            throw std::runtime_error("Failed opening handle to " + this->name_ + " in process list.");
            return;
        }
    }

    // capture handle modules snapshot
    this->handle_modules_snapshot_ = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->pid_.value());

    // check for handle modules snapshot
    if (!this->handle_modules_snapshot_.has_value()) {
        throw std::runtime_error("Failed opening handle to " + this->name_ + " in process list.");
        return;
    } else {
        if (this->handle_modules_snapshot_.value() == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Invalid handle value to " + this->name_ + " in process list.");
            return;
        }
    }
}

ctx::~ctx() {
    // don't leak handles
    if (this->handle_.has_value()) {
        CloseHandle(this->handle_.value());
    }

    if (this->handle_modules_snapshot_.has_value()) {
        CloseHandle(this->handle_modules_snapshot_.value());
    }
}

const std::string& ctx::get_name() const {
    return this->name_;
}

std::optional<uint32_t> ctx::get_pid() const {
    return this->pid_;
}

std::optional<HANDLE> ctx::get_handle() const {
    return this->handle_;
}

std::optional<HANDLE> ctx::get_handle_modules_snapshot() const {
    return this->handle_modules_snapshot_;
}

std::optional<module> ctx::get_module(std::string&& name) const {
    const size_t hash = detail::hasher<>::get(name.c_str(), name.size());

    if (this->modules_.contains(hash)) {
        return this->modules_.at(hash);
    }

    return std::nullopt;
}

std::optional<module> ctx::capture_module(std::string&& name) {
    const size_t name_hash = detail::hasher<>::get(name.c_str(), name.size());
    if (this->modules_.contains(name_hash)) {
        return this->modules_.at(name_hash);
    }

    MODULEENTRY32 buffer {.dwSize = sizeof(MODULEENTRY32)};
    if (get_handle_modules_snapshot().has_value()) {
        const HANDLE& snapshot = get_handle_modules_snapshot().value();
        for (bool copied = Module32First(snapshot, &buffer); copied; copied = Module32Next(snapshot, &buffer)) {
            const size_t current_hash = detail::hasher<>::get(buffer.szModule, strlen(buffer.szModule));

            if (name_hash == current_hash) {
                this->modules_[name_hash] = module {
                    buffer.modBaseAddr,
                    buffer.modBaseSize};
                return this->modules_[name_hash];
            }
        }
    }

    return std::nullopt;
}

void ctx::capture_all_modules() {
    MODULEENTRY32 buffer {.dwSize = sizeof(MODULEENTRY32)};
    if (get_handle_modules_snapshot().has_value()) {
        const HANDLE& snapshot = get_handle_modules_snapshot().value();
        for (bool copied = Module32First(snapshot, &buffer); copied; copied = Module32Next(snapshot, &buffer)) {
            const size_t current_hash    = detail::hasher<>::get(buffer.szModule, strlen(buffer.szModule));
            this->modules_[current_hash] = module {
                buffer.modBaseAddr,
                buffer.modBaseSize};
        }
    } else {
        throw std::runtime_error("No available handle to the modules snapshot.");
    }
}