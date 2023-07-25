
#include<openssl/sha.h>
#include <cstddef>
#include <cstring>
#include <vector>
#include <fstream>
#include <array>
#include <iostream>

namespace merkle {

    static inline void serialise_uint64_t(uint64_t n, std::vector<uint8_t>& bytes)
  {
    size_t sz = sizeof(uint64_t);

    bytes.reserve(bytes.size() + sz);
    for (uint64_t i = 0; i < sz; i++)
      bytes.push_back((n >> (8 * (sz - i - 1))) & 0xFF);
  }

    static inline uint64_t deserialise_uint64_t(
    const std::vector<uint8_t>& bytes, size_t& index)
  {
    uint64_t r = 0;
    uint64_t sz = sizeof(uint64_t);
    for (uint64_t i = 0; i < sz; i++)
      r |= static_cast<uint64_t>(bytes.at(index++)) << (8 * (sz - i - 1));
    return r;
  }

  static inline void serialise_uint64_t(uint64_t n, uint8_t* bytes)
  {
    size_t sz = sizeof(uint64_t);
    
    for (uint64_t i = 0; i < sz; i++)
      bytes[i] = (n >> (8 * (sz - i - 1))) & 0xFF;
  }



  /// @brief Template for fixed-size hashes
  /// @tparam SIZE Size of the hash in number of bytes
  template <size_t SIZE>
  struct HashT
  {
    /// Holds the hash bytes
    uint8_t bytes[SIZE];

    /// @brief Constructs a Hash with all bytes set to zero
    HashT<SIZE>()
    {
      std::fill(bytes, bytes + SIZE, 0);
    }

    /// @brief Constructs a Hash from a byte buffer
    /// @param bytes Buffer with hash value
    HashT<SIZE>(const uint8_t* bytes)
    {
      std::copy(bytes, bytes + SIZE, this->bytes);
    }

    /// @brief Constructs a Hash from a string
    /// @param s String to read the hash value from
    HashT<SIZE>(const std::string& s)
    {
      if (s.length() != 2 * SIZE)
        throw std::runtime_error("invalid hash string");
      for (size_t i = 0; i < SIZE; i++)
      {
        int tmp;
        sscanf(s.c_str() + 2 * i, "%02x", &tmp);
        bytes[i] = tmp;
      }
    }

    /// @brief Deserialises a Hash from a vector of bytes
    /// @param bytes Vector to read the hash value from
    HashT<SIZE>(const std::vector<uint8_t>& bytes)
    {
      if (bytes.size() < SIZE)
        throw std::runtime_error("not enough bytes");
      deserialise(bytes);
    }

    /// @brief Deserialises a Hash from a vector of bytes
    /// @param bytes Vector to read the hash value from
    /// @param position Position of the first byte in @p bytes
    HashT<SIZE>(const std::vector<uint8_t>& bytes, size_t& position)
    {
      if (bytes.size() - position < SIZE)
        throw std::runtime_error("not enough bytes");
      deserialise(bytes, position);
    }

    /// @brief Deserialises a Hash from an array of bytes
    /// @param bytes Array to read the hash value from
    HashT<SIZE>(const std::array<uint8_t, SIZE>& bytes)
    {
      std::copy(bytes.data(), bytes.data() + SIZE, this->bytes);
    }

    void change(int i, uint8_t n) {
      bytes[i] = n;
    }

    /// @brief The size of the hash (in number of bytes)
    size_t size() const
    {
      return SIZE;
    }

    /// @brief zeros out all bytes in the hash
    void zero()
    {
      std::fill(bytes, bytes + SIZE, 0);
    }

    /// @brief The size of the serialisation of the hash (in number of bytes)
    size_t serialised_size() const
    {
      return SIZE;
    }

    uint64_t to_uint64() {
      uint64_t res = 0;
      for (size_t i = 0; i < SIZE; i++) {
        res += bytes[i];
      }
      return res;
    }

    /// @brief Convert a hash to a hex-encoded string
    /// @param num_bytes The maximum number of bytes to convert
    /// @param lower_case Enables lower-case hex characters
    std::string to_string(size_t num_bytes = SIZE, bool lower_case = true) const
    {
      size_t num_chars = 2 * num_bytes;
      std::string r(num_chars, '_');
      for (size_t i = 0; i < num_bytes; i++)
        snprintf(
          const_cast<char*>(r.data() + 2 * i),
          num_chars + 1 - 2 * i,
          lower_case ? "%02x" : "%02X",
          bytes[i]);
      return r;
    }

    /// @brief Hash assignment operator
    HashT<SIZE> operator=(const HashT<SIZE>& other)
    {
      std::copy(other.bytes, other.bytes + SIZE, bytes);
      return *this;
    }

    /// @brief Hash equality operator
    bool operator==(const HashT<SIZE>& other) const
    {
      return memcmp(bytes, other.bytes, SIZE) == 0;
    }

    /// @brief Hash inequality operator
    bool operator!=(const HashT<SIZE>& other) const
    {
      return memcmp(bytes, other.bytes, SIZE) != 0;
    }

    /// @brief Hash less operator
    bool operator<(const HashT<SIZE>& other) const
    {
      return memcmp(bytes, other.bytes, SIZE) < 0;
    }

    /// @brief Hash less or equal operator
    bool operator<=(const HashT<SIZE>& other) const
    {
      return memcmp(bytes, other.bytes, SIZE) <= 0;
    }

    /// @brief Hash modulus operator
    int operator%(int n) const
    {
      return bytes[SIZE-1] % n;
    }

    /// @brief Hash subtraction operator assumes that current hash is bigger than other
    HashT<SIZE> operator-(const HashT<SIZE>& other) const
    {
      uint8_t res[SIZE];
      int diff;
      int borrow = 0;

      for (size_t i = SIZE - 1; i <= 0; i--) {
        diff = bytes[i] - other.bytes[i] - borrow;
        if(diff < 0) {
          diff += 256;
          borrow = 1;
        }
        else {
          borrow = 0;
        }
      }

      return HashT<SIZE>(res);
    }

    /// @brief Serialises a hash
    /// @param buffer Buffer to serialise to
    void serialise(std::vector<uint8_t>& buffer) const
    {
      for (auto& b : bytes)
        buffer.push_back(b);
    }

    /// @brief Deserialises a hash
    /// @param buffer Buffer to read the hash from
    /// @param position Position of the first byte in @p bytes
    void deserialise(const std::vector<uint8_t>& buffer, size_t& position)
    {
      if (buffer.size() - position < SIZE)
        throw std::runtime_error("not enough bytes");
      for (size_t i = 0; i < sizeof(bytes); i++)
        bytes[i] = buffer[position++];
    }

    /// @brief Deserialises a hash
    /// @param buffer Buffer to read the hash from
    void deserialise(const std::vector<uint8_t>& buffer)
    {
      size_t position = 0;
      deserialise(buffer, position);
    }

    /// @brief Conversion operator to vector of bytes
    operator std::vector<uint8_t>() const
    {
      std::vector<uint8_t> bytes;
      serialise(bytes);
      return bytes;
    }
  };

  /// @brief Template for Merkle trees
  /// @tparam HASH_SIZE Size of each hash in number of bytes
  /// @tparam HASH_FUNCTION The hash function
  template <
    size_t HASH_SIZE,
    void HASH_FUNCTION(
      const std::vector<HashT<HASH_SIZE>>& values,
      size_t start,
      size_t len,
      HashT<HASH_SIZE>& out),
    size_t FANOUT,
    size_t LEAVES>
  class TreeT {
    public:
    /// @brief Constructs an empty tree
    TreeT() {}

    /// @brief Constructs a tree from vector of bytes
    TreeT(const std::vector<uint8_t> &bytes, uint64_t offset) {
      file_offset = offset;
      std::vector<HashT<HASH_SIZE>> values;
      for (size_t i = 0; i < LEAVES; i++) {
        size_t position = i * HASH_SIZE;
        HashT<HASH_SIZE> hash(bytes, position);
        values.push_back(hash);
      }

      build(values);
    }

    void compute_leaves() {
      for (size_t i = 0; i < LEAVES; i++) {
        sha256_leaf(nodes[i], file_offset+i, nodes[i]);
      }
    }


    /// @brief Builds a tree from a vector of 
    void build(const std::vector<HashT<HASH_SIZE>> &values) {
      if (values.empty()) {
        throw std::runtime_error("Cannot build a Merkle Tree with an empty vector");
      }

      nodes = values;
      int total = (FANOUT * LEAVES - 1) / (FANOUT - 1);

      for (size_t i = 0; i < total - LEAVES; i++) {
        HashT<HASH_SIZE> hash;
        sha256(nodes, i*FANOUT, FANOUT, hash);
        nodes.push_back(hash);
      }
    }

    HashT<HASH_SIZE> root() {
      return nodes.back();
    }

    void serialize(std::string filename) {
      std::ifstream fi(filename, std::ifstream::binary);
      if (fi.good())
        throw std::runtime_error("Cannot serialize with given filename");
      fi.close();
      
      std::ofstream f(filename, std::ofstream::binary);
        std::vector<uint8_t> bytes;
        serialise_uint64_t(file_offset, bytes);
        for(HashT<HASH_SIZE> h: nodes) {
          h.serialise(bytes);
        }
        for (char b : bytes)
          f.write(&b, 1);
        f.close();
    }

    /// @brief Vector of nodes current in the tree
    std::vector<HashT<HASH_SIZE>> nodes;
    uint64_t file_offset;
  };

  static inline void sha256(const std::vector<HashT<32>>& values, size_t start, size_t len, HashT<32>& out) {
    uint8_t block[32 * len];
    for (size_t i = 0; i < len; i++) {
      memcpy(&block[i * 32], values.at(start + i).bytes, 32);
    }
    SHA256(block, sizeof(block), out.bytes);
  }
}