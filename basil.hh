/**
 * @file basil.hh
 * @author Cristei Gabriel-Marian (cristei.g772@gmail.com)
 * @brief Simple 32-bit Windows Process Memory Class.
 * @version 0.1
 * @date 2021-09-07
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef BASIL_DEF
#define BASIL_DEF

#include <Windows.h>
#include <utility>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <array>

namespace basil {
namespace detail {
    // constants
    constexpr DWORD local_pid = 0;
    constexpr DWORD page_size = 0x1000;

    // types
    using page = std::array<uint8_t, page_size>;

    // hasher
    template<size_t seed = 0x543C730D, size_t prime = 0x1000931>
    struct hasher {
        constexpr static size_t get(const char* key, size_t len) {
            size_t hash = seed;

            for (auto i = 0; i < len; ++i) {
                const uint8_t val = key[i];
                hash ^= val;
                hash *= prime;
            }

            return hash;
        }
    };
}  // namespace detail

namespace impl {
    template<typename T>
    [[nodiscard]] std::optional<std::pair<T, size_t>> read_process_memory(HANDLE handle, uintptr_t at) {
        T possible_result {};
        SIZE_T bytes_read = 0;
        // this will fail if, say, the page from at to at+sizeof(T) is unreadable, or if there's only a partial copy
        if (!ReadProcessMemory(handle, (LPCVOID)(at), (LPVOID)(&possible_result), sizeof(T), &bytes_read)) {
            return std::nullopt;
        }

        return std::make_pair(possible_result, bytes_read);
    }

    template<typename T>
    std::pair<bool, size_t> write_process_memory(HANDLE handle, uintptr_t at, const T value) {
        SIZE_T bytes_read = 0;
        return std::make_pair(WriteProcessMemory(handle, (LPVOID)(at), &value, sizeof(T), &bytes_read), bytes_read);
    }

    template<size_t N>
    [[nodiscard]] std::optional<uintptr_t> pattern_scan_process(HANDLE handle, const std::array<int, N>& pattern, uintptr_t start, uintptr_t end) {
        const size_t array_size = pattern.size();
        const uintptr_t reach   = end - array_size;
        for (uintptr_t i = start; i < reach; i = min(i + detail::page_size, reach)) {
            const auto read = read_process_memory<detail::page>(handle, i);
            if (!read.has_value()) {
                continue;
            }

            const auto& [bytes, bytes_read] = read.value();
            for (size_t j = 0; j < detail::page_size - array_size; ++j) {
                bool found = true;
                for (size_t k = 0; k < array_size; ++k) {
                    if (bytes[j + k] != pattern[k] && pattern[k] != -1) {
                        found = false;
                        break;
                    }
                }

                if (found) {
                    return i + j;
                }
            }
        }

        return std::nullopt;
    }
}  // namespace impl

struct module {
    uint8_t* start_;
    size_t size_;
};

struct ctx {
    //	constructors

    ctx() = delete;
    /// returns context of specified process
    [[nodiscard]] ctx(std::string&& name);
    ~ctx();

    // copy/move constructors/assignment operators

    ctx(const ctx&) = default;
    ctx(ctx&&)      = default;

    ctx& operator=(const ctx&) = default;
    ctx& operator=(ctx&&) = default;

    // getters

    const std::string& get_name() const;
    std::optional<uint32_t> get_pid() const;
    std::optional<HANDLE> get_handle() const;
    std::optional<HANDLE> get_handle_modules_snapshot() const;

    std::optional<module> get_module(std::string&& name) const;

    // utilities
    std::optional<module> capture_module(std::string&& name);
    void capture_all_modules();

    template<typename T>
    [[nodiscard]] inline std::optional<std::pair<T, size_t>> read_memory(uintptr_t at) const;

    template<typename T>
    [[nodiscard]] inline std::optional<std::pair<T, size_t>> read_module_memory(std::string&& name, uintptr_t at) const;

    template<typename T>
    inline std::pair<bool, size_t> write_memory(uintptr_t at, const T value) const;

    template<typename T>
    inline std::pair<bool, size_t> write_module_memory(std::string&& name, uintptr_t at, const T value) const;

    template<size_t N>
    [[nodiscard]] inline std::optional<uintptr_t> pattern_scan(const std::array<int, N>& pattern, uintptr_t start, uintptr_t end) const;

    template<size_t N>
    [[nodiscard]] inline std::optional<uintptr_t> pattern_scan_module(std::string&& name, const std::array<int, N>& pattern) const;

  private:
    std::string name_;
    std::optional<uint32_t> pid_;
    std::optional<HANDLE> handle_;
    std::optional<HANDLE> handle_modules_snapshot_;

    std::unordered_map<size_t, module> modules_;
};

template<typename T>
std::optional<std::pair<T, size_t>> ctx::read_memory(uintptr_t at) const {
    return impl::read_process_memory<T>(this->handle_.value(), at);
}

template<typename T>
std::optional<std::pair<T, size_t>> ctx::read_module_memory(std::string&& name, uintptr_t at) const {
    const std::optional<module> module = capture_module(std::move(name));

    if (module.has_value()) {
        const uintptr_t start = (uintptr_t)(module.value().start_);
        return read_memory<T>(start + at);
    }

    return std::nullopt;
}

template<typename T>
std::pair<bool, size_t> ctx::write_memory(uintptr_t at, const T value) const {
    return impl::write_process_memory<T>(this->handle_.value(), at, value);
}

template<typename T>
std::pair<bool, size_t> ctx::write_module_memory(std::string&& name, uintptr_t at, const T value) const {
    const std::optional<module> module = capture_module(std::move(name));

    if (module.has_value()) {
        const uintptr_t start = (uintptr_t)(module.value().start_);
        return write_memory<T>(start + at, value);
    }

    return std::make_pair(false, 0);
}

template<size_t N>
std::optional<uintptr_t> ctx::pattern_scan(const std::array<int, N>& pattern, uintptr_t start, uintptr_t end) const {
    return impl::pattern_scan_process<N>(this->handle_.value(), pattern, start, end);
}

template<size_t N>
std::optional<uintptr_t> ctx::pattern_scan_module(std::string&& name, const std::array<int, N>& pattern) const {
    const std::optional<module> module = capture_module(std::move(name));

    if (module.has_value()) {
        const auto& [start, end]      = module.value();
        const uintptr_t start_address = (uintptr_t)(start);
        return pattern_scan<N>(pattern, start_address, start_address + end);
    }

    return std::nullopt;
}
}  // namespace basil

#endif