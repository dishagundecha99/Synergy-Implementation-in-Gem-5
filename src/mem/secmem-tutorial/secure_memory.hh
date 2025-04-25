#ifndef __SECURE_MEMORY_HH__
#define __SECURE_MEMORY_HH__

#include "mem/port.hh"
#include "params/SecureMemory.hh"
#include "sim/sim_object.hh"
#include "base/statistics.hh"

#include <deque>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <string>
#include <iostream>

namespace gem5::memory {

class SecureMemory : public SimObject {
  public:
    class CpuSidePort : public ResponsePort {
      private:
        SecureMemory *parent;
        bool blocked;
        bool need_retry;
        std::deque<PacketPtr> blocked_packets;
      public:
        CpuSidePort(const std::string &name, SecureMemory *parent);
        AddrRangeList getAddrRanges() const override;
        void recvFunctional(PacketPtr pkt) override;
        Tick recvAtomic(PacketPtr pkt) override;
        void sendPacket(PacketPtr pkt);
        bool recvTimingReq(PacketPtr pkt) override;
        void recvRespRetry() override;
    };

    class MemSidePort : public RequestPort {
      private:
        SecureMemory *parent;
        std::deque<PacketPtr> blocked_packets;
      public:
        MemSidePort(const std::string &name, SecureMemory *parent);
        bool isSnooping() const override;
        void recvRangeChange() override;
        bool recvTimingResp(PacketPtr pkt) override;
        void recvReqRetry() override;
        void sendPacket(PacketPtr pkt);
    };

    SecureMemory(const SecureMemoryParams *p);
    Port &getPort(const std::string &if_name, PortID idx = InvalidPortID) override;
    void startup() override;

  private:
    CpuSidePort cpu_port;
    MemSidePort mem_port;

    // fixed sizes
    static constexpr size_t BLOCK_SIZE = 72; // 64B data + 8B MAC
    static constexpr size_t DATA_SIZE = 64;
    static constexpr size_t HMAC_SIZE = 8;
    static constexpr int ARITY = 2;

    uint64_t start_addr;
    std::vector<std::vector<uint64_t>> merkle_levels;

    // shadow storage and write counts
    std::unordered_map<uint64_t, std::vector<uint8_t>> block_data;
    std::unordered_map<uint64_t, size_t> write_count;

    uint64_t computeMAC(const uint8_t* data, size_t len);
    bool validateMAC(const std::vector<uint8_t> &block);
    bool validateParity(const std::vector<uint8_t> &block);
    uint64_t combineHashes(uint64_t left, uint64_t right);

    void updateMerkleTree(uint64_t block_addr, uint64_t block_mac);
    void verifyMerklePath(uint64_t block_addr);

    bool handleRequest(PacketPtr pkt);
    bool handleResponse(PacketPtr pkt);

    class SecureMemoryStats : public statistics::Group {
      public:
        SecureMemoryStats(SecureMemory &m);
        void regStats() override;

        statistics::Scalar requests_processed;
        statistics::Scalar responses_processed;
      private:
        SecureMemory &m;
    } stats;
};

} // namespace gem5::memory

#endif // __SECURE_MEMORY_HH__
