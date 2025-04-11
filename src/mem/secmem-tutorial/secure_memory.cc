#include "mem/secmem-tutorial/secure_memory.hh"
#include <cstdint>
#include <cstring>
#include <iostream>

gem5::memory::SecureMemory::CpuSidePort::CpuSidePort(const std::string &name, SecureMemory *parent)
    : ResponsePort(name), parent(parent), blocked(false), need_retry(false) {}

gem5::memory::SecureMemory::MemSidePort::MemSidePort(const std::string &name, SecureMemory *parent)
    : RequestPort(name), parent(parent) {}

namespace gem5::memory {

uint64_t SecureMemory::computeMAC(const uint8_t* data, size_t len) {
    uint64_t mac = 0;
    for (size_t i = 0; i < len; ++i) {
        mac = (mac * 131) + data[i];
    }
    return mac;
}

bool SecureMemory::validateMAC(const uint8_t* data_with_mac) {
    uint64_t received_mac;
    memcpy(&received_mac, data_with_mac + DATA_SIZE, sizeof(uint64_t));
    uint64_t computed_mac = computeMAC(data_with_mac, DATA_SIZE);
    return received_mac == computed_mac;
}

SecureMemory::SecureMemory(const SecureMemoryParams *p)
    : SimObject(*p),
      cpu_port(p->name + ".cpu_side", this),
      mem_port(p->name + ".mem_side", this),
      stats(*this) {}

Port& SecureMemory::getPort(const std::string &if_name, PortID idx) {
    if (if_name == "mem_side")
        return mem_port;
    else if (if_name == "cpu_side")
        return cpu_port;
    return SimObject::getPort(if_name, idx);
}

void SecureMemory::startup() {
    AddrRangeList ranges = mem_port.getAddrRanges();
    assert(ranges.size() == 1);
    uint64_t start = ranges.front().start();
    uint64_t end = ranges.front().end();

    uint64_t hmac_bytes = ((end - start) / BLOCK_SIZE) * HMAC_SIZE;
    uint64_t counter_bytes = ((end - start) / PAGE_SIZE) * BLOCK_SIZE;

    uint64_t tree_offset = end + hmac_bytes;
    integrity_levels.push_front(start);
    integrity_levels.push_front(tree_offset);

    uint64_t bytes_on_level = counter_bytes;
    do {
        integrity_levels.push_front(tree_offset + bytes_on_level);
        tree_offset += bytes_on_level;
        bytes_on_level /= ARITY;
    } while (bytes_on_level > 1);

    integrity_levels.push_front(end);
    integrity_levels.shrink_to_fit();
    data_level = integrity_levels.size() - 1;
    counter_level = data_level - 1;
}

bool SecureMemory::handleRequest(PacketPtr pkt) {
    if (pkt->isWrite() && pkt->hasData()) {
        if (pkt->getSize() == BLOCK_SIZE) {
            uint8_t* full_block = pkt->getPtr<uint8_t>();
            uint64_t new_mac = computeMAC(full_block, DATA_SIZE);
            memcpy(full_block + DATA_SIZE, &new_mac, sizeof(uint64_t));
            std::cout << "[DEBUG] Write at 0x" << std::hex << pkt->getAddr()
                      << " computed MAC: 0x" << new_mac << std::endl;
        } else {
            std::cout << "[WARNING] Write packet at addr 0x" << std::hex << pkt->getAddr() 
                      << " has size " << std::dec << pkt->getSize() 
                      << " bytes (expected " << BLOCK_SIZE << " bytes)." << std::endl;
        }
    }
    mem_port.sendPacket(pkt);
    return true;
}

bool SecureMemory::handleResponse(PacketPtr pkt) {
    if (pkt->isRead() && pkt->getAddr() < integrity_levels[hmac_level]) {
        uint8_t* full_block = pkt->getPtr<uint8_t>();
        uint64_t stored_mac;
        memcpy(&stored_mac, full_block + DATA_SIZE, sizeof(uint64_t));
        uint64_t computed_mac = computeMAC(full_block, DATA_SIZE);
        if (stored_mac != computed_mac) {
            std::cout << "[ERROR] MAC validation failed at address 0x" << std::hex 
                      << pkt->getAddr() << ". Stored MAC: 0x" << stored_mac 
                      << ", Computed MAC: 0x" << computed_mac << std::endl;
            return false;
        }
    }
    std::cout << "[DEBUG] MAC verified successfully at 0x" << std::hex 
              << pkt->getAddr() << std::endl;
    cpu_port.sendPacket(pkt);
    return true;
}

Tick SecureMemory::CpuSidePort::recvAtomic(PacketPtr pkt) {
    return parent->mem_port.sendAtomic(pkt);
}

void SecureMemory::CpuSidePort::recvFunctional(PacketPtr pkt) {
    parent->mem_port.sendFunctional(pkt);
}

void SecureMemory::CpuSidePort::recvRespRetry() {
}

AddrRangeList SecureMemory::CpuSidePort::getAddrRanges() const {
    return parent->mem_port.getAddrRanges();
}

bool SecureMemory::CpuSidePort::recvTimingReq(PacketPtr pkt) {
    if (blocked || !parent->handleRequest(pkt)) {
        need_retry = true;
        return false;
    }
    return true;
}

void SecureMemory::CpuSidePort::sendPacket(PacketPtr pkt) {
    blocked_packets.push_back(pkt);
    PacketPtr to_send = blocked_packets.front();
    if (sendTimingResp(to_send)) {
        blocked_packets.pop_front();
        if (blocked)
            blocked = false;
        if (need_retry) {
            sendRetryReq();
            need_retry = false;
        }
    }
}

bool SecureMemory::MemSidePort::isSnooping() const {
    return false;
}

void SecureMemory::MemSidePort::recvRangeChange() {
    parent->cpu_port.sendRangeChange();
}

bool SecureMemory::MemSidePort::recvTimingResp(PacketPtr pkt) {
    return parent->handleResponse(pkt);
}

void SecureMemory::MemSidePort::recvReqRetry() {
    assert(!blocked_packets.empty());
    while (!blocked_packets.empty() && sendTimingReq(blocked_packets.front())) {
        blocked_packets.pop_front();
    }
}

void SecureMemory::MemSidePort::sendPacket(PacketPtr pkt) {
    if (!sendTimingReq(pkt))
        blocked_packets.push_back(pkt);
}

SecureMemory::SecureMemoryStats::SecureMemoryStats(SecureMemory &m)
    : statistics::Group(&m), m(m),
      ADD_STAT(requests_processed, statistics::units::Count::get(),
               "number of requests from the processor side that we've handled"),
      ADD_STAT(responses_processed, statistics::units::Count::get(),
               "number of memory responses that we've handled") {}

void SecureMemory::SecureMemoryStats::regStats() {
    statistics::Group::regStats();
}

}; 

gem5::memory::SecureMemory *
gem5::SecureMemoryParams::create() const {
    return new gem5::memory::SecureMemory(this);
}
