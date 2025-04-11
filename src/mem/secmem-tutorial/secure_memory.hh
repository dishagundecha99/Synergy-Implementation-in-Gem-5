#ifndef __MEM_SECURE_MEMORY__
#define __MEM_SECURE_MEMORY__

#include "base/statistics.hh"
#include "mem/port.hh"
#include "params/SecureMemory.hh"
#include "sim/sim_object.hh"

#include <set>
#include <deque>
#include <list>

#define ARITY 8
#define BLOCK_SIZE 72
#define HMAC_SIZE 8
#define DATA_SIZE (BLOCK_SIZE - HMAC_SIZE)
#define PAGE_SIZE 4096

namespace gem5::memory {

class SecureMemory : public SimObject
{
  private:
    class CpuSidePort : public ResponsePort {
      private:
        SecureMemory *parent;
        bool blocked;
        bool need_retry;
        std::list<PacketPtr> blocked_packets;
      public:
        CpuSidePort(const std::string &name, SecureMemory *parent);
        Tick recvAtomic(PacketPtr pkt) override;
        void recvFunctional(PacketPtr pkt) override;
        bool recvTimingReq(PacketPtr pkt) override;
        void recvRespRetry() override;
        AddrRangeList getAddrRanges() const override;
        void sendPacket(PacketPtr pkt);
    };

    class MemSidePort : public RequestPort {
      private:
        SecureMemory *parent;
        std::list<PacketPtr> blocked_packets;
      public:
        MemSidePort(const std::string &name, SecureMemory *parent);
        bool isSnooping() const override;
        bool recvTimingResp(PacketPtr pkt) override;
        void recvReqRetry() override;
        void recvRangeChange() override;
        void sendPacket(PacketPtr pkt);
    };

    CpuSidePort cpu_port;
    MemSidePort mem_port;

    std::deque<uint64_t> integrity_levels;
    int root_level = 1;
    int hmac_level = 0;
    int data_level;
    int counter_level;

    std::set<uint64_t> pending_tree_authentication;
    std::set<uint64_t> pending_hmac;
    std::set<PacketPtr> pending_untrusted_packets;

    bool handleRequest(PacketPtr pkt);
    bool handleResponse(PacketPtr pkt);
    uint64_t getHmacAddr(uint64_t child_addr);
    uint64_t getParentAddr(uint64_t child_addr);
    void verifyChildren(PacketPtr parent);

    // The MAC is computed over the first 64 bytes of the block.
    uint64_t computeMAC(const uint8_t* data, size_t len);
    bool validateMAC(const uint8_t* data_with_mac);

    // New parity function that checks the integrity across all 9 chips. We assume the block is arranged in 9 consecutive 8-byte chunks So, For each of the 8 columns, the XOR of the 9 bytes must be zero.
    bool validateParity(const uint8_t* block);

  public:
    SecureMemory(const SecureMemoryParams *p);
    Port &getPort(const std::string &if_name, PortID idx = InvalidPortID) override;
    void startup() override;

    struct SecureMemoryStats : public statistics::Group {
        SecureMemoryStats(SecureMemory &m);
        void regStats() override;
        const SecureMemory &m;
        statistics::Scalar requests_processed;
        statistics::Scalar responses_processed;
    };

    SecureMemoryStats stats;
};

}; // namespace gem5::memory

#endif // __MEM_SECURE_MEMORY__
