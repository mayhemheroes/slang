//------------------------------------------------------------------------------
//! @file CopyPtr.h
//! @brief Value-copying smart pointer
//
// SPDX-FileCopyrightText: Michael Popoloski
// SPDX-License-Identifier: MIT
//------------------------------------------------------------------------------
#pragma once

namespace slang {

/// A smart pointer that allocates its pointee on the heap and provides value copy
/// semantics. Unlike unique_ptr, the pointer can be copied. Unlike shared_ptr,
/// the pointee is not shared; each copy results in a new instance.
template<typename T>
class CopyPtr {
public:
    using pointer = T*;

    CopyPtr() {}
    CopyPtr(std::nullptr_t) {}
    ~CopyPtr() { delete ptr; }

    CopyPtr(const CopyPtr& other) : ptr(new T(*other.ptr)) {}
    CopyPtr(CopyPtr&& other) noexcept : ptr(std::exchange(other.ptr, nullptr)) {}

    template<typename U, typename = std::enable_if_t<std::is_convertible<U*, T*>::value>>
    CopyPtr(const U& other) : ptr(new T(other)) {}

    template<typename U, typename = std::enable_if_t<std::is_convertible<U*, T*>::value>>
    CopyPtr(U&& other) noexcept : ptr(new T(std::forward<U>(other))) {}

    T* get() { return ptr; }
    const T* get() const { return ptr; }

    T* operator->() { return get(); }
    const T* operator->() const { return get(); }
    decltype(auto) operator*() { return *get(); }
    decltype(auto) operator*() const { return *get(); }

    explicit operator bool() const { return ptr != nullptr; }

    CopyPtr& operator=(std::nullptr_t) {
        ptr = nullptr;
        return *this;
    }

    template<typename U, typename = std::enable_if_t<std::is_convertible<U*, T*>::value>>
    CopyPtr& operator=(const U& other) {
        delete ptr;
        ptr = new T(other);
        return *this;
    }

    template<typename U, typename = std::enable_if_t<std::is_convertible<U*, T*>::value>>
    CopyPtr& operator=(U&& other) {
        delete ptr;
        ptr = new T(std::forward<U>(other));
        return *this;
    }

    CopyPtr& operator=(const CopyPtr& other) {
        if (this != &other) {
            delete ptr;
            ptr = new T(*other.ptr);
        }
        return *this;
    }

    CopyPtr& operator=(CopyPtr&& other) noexcept {
        if (this != &other) {
            delete ptr;
            ptr = std::exchange(other.ptr, nullptr);
        }
        return *this;
    }

private:
    T* ptr = nullptr;
};

template<typename T>
std::ostream& operator<<(std::ostream& os, const CopyPtr<T>& val) {
    os << val.get();
    return os;
}

template<typename T, typename U>
auto operator==(const CopyPtr<T>& lhs, const CopyPtr<U>& rhs) -> decltype(lhs.get() == rhs.get()) {
    return lhs.get() == rhs.get();
}

template<typename T, typename U>
auto operator!=(const CopyPtr<T>& lhs, const CopyPtr<U>& rhs) -> decltype(lhs.get() != rhs.get()) {
    return lhs.get() != rhs.get();
}

template<typename T, typename U>
auto operator<(const CopyPtr<T>& lhs, const CopyPtr<U>& rhs) -> decltype(lhs.get() < rhs.get()) {
    return lhs.get() < rhs.get();
}

template<typename T, typename U>
auto operator<=(const CopyPtr<T>& lhs, const CopyPtr<U>& rhs) -> decltype(lhs.get() <= rhs.get()) {
    return lhs.get() <= rhs.get();
}

template<typename T, typename U>
auto operator>(const CopyPtr<T>& lhs, const CopyPtr<U>& rhs) -> decltype(lhs.get() > rhs.get()) {
    return lhs.get() > rhs.get();
}

template<typename T, typename U>
auto operator>=(const CopyPtr<T>& lhs, const CopyPtr<U>& rhs) -> decltype(lhs.get() >= rhs.get()) {
    return lhs.get() >= rhs.get();
}

} // namespace slang

namespace std {

template<typename T>
struct hash<slang::CopyPtr<T>> {
    std::size_t operator()(const slang::CopyPtr<T>& value) const { return hash<T>{}(value.get()); }
};

} // namespace std
