#include "mem/secmem-tutorial/secure_memory.hh"
#include <cstdint>
#include <cstring>
#include <cassert>
#include <iostream>

namespace gem5::memory {

SecureMemory::SecureMemory(const SecureMemoryParams *p)
    : SimObject(*p),
      cpu_port(p->name + ".cpu_side", this),
      mem_port(p->name + ".mem_side", this),
      stats(*this)
{
    // no-op
}

// port constructors
SecureMemory::CpuSidePort::CpuSidePort(const std::string &name, SecureMemory *parent)
    : ResponsePort(name), parent(parent), blocked(false), need_retry(false) {}
SecureMemory::MemSidePort::MemSidePort(const std::string &name, SecureMemory *parent)
    : RequestPort(name), parent(parent) {}

Port &
SecureMemory::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "mem_side")  return mem_port;
    if (if_name == "cpu_side") return cpu_port;
    return SimObject::getPort(if_name, idx);
}

uint64_t SecureMemory::computeMAC(const uint8_t* data, size_t len) {
    uint64_t mac = 0;
    for (size_t i = 0; i < len; ++i)
        mac = mac * 131 + data[i];
    return mac;
}

bool SecureMemory::validateMAC(const std::vector<uint8_t> &block) {
    uint64_t received_mac = 0;
    std::memcpy(&received_mac, block.data() + DATA_SIZE, sizeof(received_mac));
    uint64_t expected_mac = computeMAC(block.data(), DATA_SIZE);
    if (received_mac != expected_mac) {
        std::cerr << "[ERROR] MAC expected=0x" << std::hex << expected_mac
                  << ", got=0x" << received_mac << std::dec << std::endl;
        return false;
    }
    return true;
}

bool SecureMemory::validateParity(const std::vector<uint8_t> &block) {
    // Even parity: each of the DATA_SIZE bytes must XOR to zero across rows
    for (size_t col = 0; col < DATA_SIZE / 8; ++col) {
        uint8_t parity = 0;
        for (size_t row = 0; row < 8; ++row)
            parity ^= block[row * (DATA_SIZE / 8) + col];
        if (parity != 0) {
            std::cerr << "[ERROR] Parity failed at column " << col << std::endl;
            return false;
        }
    }
    return true;
}

uint64_t SecureMemory::combineHashes(uint64_t left, uint64_t right) {
    return (left * 131 + right) ^ 0xA5A5A5A5A5A5A5A5ULL;
}

void SecureMemory::startup() {
    std::cout << "[DEBUG] SecureMemory startup complete." << std::endl;
    AddrRangeList ranges = mem_port.getAddrRanges();
    assert(ranges.size() == 1);
    uint64_t start = ranges.front().start();
    uint64_t end   = ranges.front().end();

    start_addr = start;
    uint64_t total_blocks = (end - start) / BLOCK_SIZE;
    uint64_t level_count = total_blocks;
    while (true) {
        merkle_levels.emplace_back(level_count, 0);
        if (level_count <= 1)
            break;
        level_count = (level_count + ARITY - 1) / ARITY;
    }
}

bool SecureMemory::handleRequest(PacketPtr pkt) {
    uint64_t addr = pkt->getAddr();
    std::cout << "[DEBUG] handleRequest addr=0x" << std::hex << addr
              << ", size=" << std::dec << pkt->getSize() << std::endl;

    if (pkt->isWrite() && pkt->hasData()) {
        write_count[addr] += pkt->getSize();
        auto &shadow = block_data[addr];
        if (shadow.empty()) shadow.resize(BLOCK_SIZE, 0);

        std::memcpy(shadow.data(), pkt->getPtr<uint8_t>(), pkt->getSize());
        uint64_t new_mac = computeMAC(shadow.data(), DATA_SIZE);
        std::memcpy(shadow.data() + DATA_SIZE, &new_mac, sizeof(new_mac));

        std::cout << "[WRITE] MAC updated at addr=0x" << std::hex << addr << std::dec << std::endl;
        updateMerkleTree(addr, new_mac);
    }

    mem_port.sendPacket(pkt);
    return true;
}

bool SecureMemory::handleResponse(PacketPtr pkt) {
    uint64_t addr = pkt->getAddr();
    std::cout << "[DEBUG] handleResponse addr=0x" << std::hex << addr << std::dec << std::endl;

    if (pkt->isRead()) {
        size_t written = write_count[addr];
        if (written < DATA_SIZE) {
            std::cout << "[SECURE] Skipping validation for partial block at 0x"
                      << std::hex << addr << std::dec << std::endl;
        } else {
            auto &shadow = block_data[addr];
            if (!validateMAC(shadow) || !validateParity(shadow)) {
                std::cerr << "[SECURE] Validation error at addr=0x" << std::hex << addr << std::dec << std::endl;
            } else {
                verifyMerklePath(addr);
                std::cout << "[SECURE] Read validation successful for addr=0x"
                          << std::hex << addr << std::dec << std::endl;
            }
        }
    }

    cpu_port.sendPacket(pkt);
    return true;
}

void SecureMemory::updateMerkleTree(uint64_t block_addr, uint64_t block_mac) {
    size_t idx = (block_addr - start_addr) / BLOCK_SIZE;
    merkle_levels[0][idx] = block_mac;
    for (size_t lvl = 1; lvl < merkle_levels.size(); ++lvl) {
        size_t parent = idx / ARITY;
        size_t left   = parent * ARITY;
        size_t right  = (left + 1 < merkle_levels[lvl-1].size()) ? left + 1 : left;
        uint64_t combined = combineHashes(
            merkle_levels[lvl-1][left],
            merkle_levels[lvl-1][right]
        );
        merkle_levels[lvl][parent] = combined;
        std::cout << "[MERKLE] Level " << lvl << " idx " << parent
                  << " hash=0x" << std::hex << combined << std::dec << std::endl;
        idx = parent;
    }
}

void SecureMemory::verifyMerklePath(uint64_t block_addr) {
    size_t idx = (block_addr - start_addr) / BLOCK_SIZE;
    for (size_t lvl = 1; lvl < merkle_levels.size(); ++lvl) {
        size_t parent = idx / ARITY;
        size_t left   = parent * ARITY;
        size_t right  = (left + 1 < merkle_levels[lvl-1].size()) ? left + 1 : left;
        uint64_t exp = merkle_levels[lvl][parent];
        uint64_t act = combineHashes(
            merkle_levels[lvl-1][left],
            merkle_levels[lvl-1][right]
        );
        if (act != exp) {
            std::cerr << "[MERKLE] Verification failed at level " << lvl
                      << " exp=0x" << std::hex << exp
                      << ", got=0x" << act << std::dec << std::endl;
            return;
        }
        idx = parent;
    }
    std::cout << "[MERKLE] Verification path OK for block addr=0x"
              << std::hex << block_addr << std::dec << std::endl;
}

// CPU-side port implementations
Tick SecureMemory::CpuSidePort::recvAtomic(PacketPtr pkt) { return parent->mem_port.sendAtomic(pkt); }
void SecureMemory::CpuSidePort::recvFunctional(PacketPtr pkt) { parent->mem_port.sendFunctional(pkt); }
AddrRangeList SecureMemory::CpuSidePort::getAddrRanges() const { return parent->mem_port.getAddrRanges(); }
bool SecureMemory::CpuSidePort::recvTimingReq(PacketPtr pkt) {
    if (blocked || !parent->handleRequest(pkt)) {
        need_retry = true;
        return false;
    }
    return true;
}
void SecureMemory::CpuSidePort::recvRespRetry() {}
void SecureMemory::CpuSidePort::sendPacket(PacketPtr pkt) {
    blocked_packets.push_back(pkt);
    PacketPtr to_send = blocked_packets.front();
    if (sendTimingResp(to_send)) {
        blocked_packets.pop_front();
        if (blocked) blocked = false;
        if (need_retry) {
            sendRetryReq();
            need_retry = false;
        }
    }
}

// Memory-side port implementations
bool SecureMemory::MemSidePort::isSnooping() const { return false; }
void SecureMemory::MemSidePort::recvRangeChange() { parent->cpu_port.sendRangeChange(); }
bool SecureMemory::MemSidePort::recvTimingResp(PacketPtr pkt) { return parent->handleResponse(pkt); }
void SecureMemory::MemSidePort::recvReqRetry() { while (!blocked_packets.empty() && sendTimingReq(blocked_packets.front())) blocked_packets.pop_front(); }
void SecureMemory::MemSidePort::sendPacket(PacketPtr pkt) { if (!sendTimingReq(pkt)) blocked_packets.push_back(pkt); }

// Stats
SecureMemory::SecureMemoryStats::SecureMemoryStats(SecureMemory &m)
    : statistics::Group(&m), m(m),
      requests_processed(this, "requests_processed", "Number of processed requests"),
      responses_processed(this, "responses_processed", "Number of processed responses") {}
void SecureMemory::SecureMemoryStats::regStats() { statistics::Group::regStats(); }

} // namespace gem5::memory

gem5::memory::SecureMemory *gem5::SecureMemoryParams::create() const { return new gem5::memory::SecureMemory(this); }
