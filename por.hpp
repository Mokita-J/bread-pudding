#include "merkle.hpp"
#include "sloth256_189.h"
#include <filesystem>
#include <fstream>
#include <set>
#include <math.h>

namespace fs = std::filesystem;

namespace por {
    int logb(int n, int b)
    {
    return log(n) / log(b);
    }

    template<typename Set>
    auto closest_element(Set& set, const typename Set::value_type& value)-> decltype(set.begin())
    {
        const auto it = set.lower_bound(value);
        if (it == set.begin())
            return it;

        const auto prev_it = std::prev(it);
        return (it == set.end() || value - *prev_it <= *it - value) ? prev_it : it;
    }

    template <
    size_t HASH_SIZE,
    size_t FANOUT,
    size_t LEAVES>
    struct ProofT {

        /// @brief The type of hashes in the tree
        typedef merkle::HashT<HASH_SIZE> Hash;

        size_t n = logb(LEAVES, FANOUT) * (FANOUT - 1) + 2;
        std::vector<Hash> hashes;

        ProofT() {}

        ProofT(const std::vector<uint8_t>& bytes, const std::vector<int>& indexes) {
            size_t position;
            size_t begin = 0;
            uint64_t offset = merkle::deserialise_uint64_t(bytes, begin);
            size_t i = 0;
            while (i < n)
            {
                position = indexes.at(i) * HASH_SIZE + begin;
                Hash h(bytes, position);
                hashes.push_back(h);
                i++;
            }
        }

        Hash root() {
            return hashes[n - 1];
        }

        Hash at(int i) {
            if (i > hashes.size())
                throw std::runtime_error("Index out of range.");
            return hashes[i];
        }

        double quality(Hash challenge) {
            std::set<Hash> nodes;

            for (size_t i = 0; i < hashes.size() - 1; i++) {
                nodes.insert(hashes[i]);
            }

            auto node = *closest_element(nodes, challenge);

            Hash h;

            for (size_t i = 0; i < HASH_SIZE/2; i++) {
                h.bytes[i] = root().bytes[i];
            }

            for (size_t i = HASH_SIZE/2; i < HASH_SIZE; i++) {
                h.bytes[i] = node.bytes[i];
            }

            Hash dif = h < challenge ? challenge - h : h - challenge;
            return (double)dif.to_uint64() / (double)(challenge.to_uint64() + h.to_uint64());
        }
    };

    
    /// @brief Template for Proof-of-Replication
    /// @tparam HASH_SIZE Size of each hash in number of bytes
    /// @tparam HASH_FUNCTION The hash function
    /// @tparam FANOUT The fanout value of the Merkle Tree
    /// @tparam LEAVES The number of leaves of the Merkle Tree
    template <
    size_t HASH_SIZE,
    void HASH_FUNCTION(
      const std::vector<merkle::HashT<HASH_SIZE>>& values,
      size_t start,
      size_t len,
      merkle::HashT<HASH_SIZE>& out),
    size_t FANOUT,
    size_t LEAVES>
    class PoRepT {
        public:
            /// @brief The type of hashes in the tree
            typedef merkle::HashT<HASH_SIZE> Hash;
            
            /// @brief The type of the tree
            typedef merkle::TreeT<HASH_SIZE, HASH_FUNCTION, FANOUT, LEAVES> Tree;

            /// @brief The type of the proof
            typedef ProofT<HASH_SIZE, FANOUT, LEAVES> Proof;


        PoRepT() {
            std::string path = "./plot";
            for (const auto & entry : fs::directory_iterator(path)) {
                Hash h(entry.path().filename());
                search.insert(h);
            }
        }

        void encode(std::vector<Hash>& v) {
            std::vector<Hash> values;
            Hash res;

            for (int i = 0; i < v.size() - 1; i++) {
                Hash hi;
                hi.bytes[HASH_SIZE-1] = i;
                values.push_back(v.back());
                values.push_back(hi);
                HASH_FUNCTION(values, 0, 2, res);
                for(uint8_t j = 0; j < HASH_SIZE; j++) {
                    v[i].bytes[j] = v[i].bytes[j] ^ res.bytes[j];
                }
                values.clear();
            }
        }

        Proof decode(Proof p, std::vector<int> indexes) {
            std::vector<Hash> values;
            Hash res;
            Proof decoded;
            Hash t;
            for (int i = 0; i < indexes.size() - 1; i++) {
                Hash hi;
                hi.bytes[HASH_SIZE-1] = indexes.at(i);
                values.push_back(p.root());
                values.push_back(hi);
                HASH_FUNCTION(values, 0, 2, res);
                for(uint8_t j = 0; j < HASH_SIZE; j++) {
                    t.bytes[j] = p.at(i).bytes[j] ^ res.bytes[j];
                }
                decoded.hashes.push_back(t);
                values.clear();
            }
            return decoded;
        }

        void plot(char* filename) {
            std::ifstream f(filename, std::ifstream::binary);
            if (!f.good())
                throw std::runtime_error("Cannot plot from invalid file");
        
            std::vector<uint8_t> bytes;
            char t;
            int offset = 0;
            while (!f.eof())
            {
                int n = LEAVES*HASH_SIZE;
                while (!f.eof() && n-- > 0)
                {
                f.read(&t, 1);
                bytes.push_back(t);
                }
                if(n < 0) {
                    Tree tree(bytes, offset);
                    encode(tree.nodes);
                    if (search.insert(tree.root()).second == false) {
                        conflicts++;
                    }
                    else {
                        tree.serialize("plot/"+tree.root().to_string());
                        plots++;
                    }
                }
                bytes.clear();
                offset++;
            }
            std::cout << "conflicts: " << conflicts << std::endl;
            std::cout << "plots: " << plots << std::endl;
            f.close();
        }

        std::vector<int> get_path_indexes(int index) {
            std::vector<int> indexes;

            int n = index / FANOUT;

            for (int i = 0; i < FANOUT; i++) {
                indexes.push_back(n*FANOUT + i);
            }

            int base = LEAVES;
            int level = 1;
            while(pow(FANOUT, level) < LEAVES) {
                int node = base + (int)index/(pow(FANOUT,level));

                int b = node / FANOUT;

                for (int i = 0; i < FANOUT; i++) {
                    if (FANOUT * b + i != node)
                        indexes.push_back(FANOUT * b + i);
                }
                base = base + (int)(LEAVES)/pow(FANOUT, level++);
            }
            indexes.push_back(base);
            return indexes;
        }

        /// @brief Generates a Proof from the plot given a challenge
        /// @param challenge 
        Proof generate_proof(Hash challenge) {
            std::vector<int> indexes = get_path_indexes(challenge % LEAVES);
            auto closest = *closest_element(search, challenge);

            std::ifstream f("plot/" + closest.to_string(), std::ifstream::binary);
            if (!f.good())
                throw std::runtime_error( "Invalid plot file" );

            std::vector<uint8_t> bytes;
            char t;
            while (!f.eof()) {
                f.read(&t, 1);
                bytes.push_back(t);
            }
            f.close();

            Proof proof(bytes, indexes);
            return proof;
        
        }

        /// @brief Computes the Merkle root from a path
        /// @param p Proof that contains the hashes from a Merkle path
        /// @param indexes Set of indexes that indicate the order of the path in the proof
        Hash compute_root(Proof* p, const std::vector<int>& indexes) {
            Hash res;
            std::vector<Hash> values;
            for (int i = 0; i < FANOUT; i++) {
                values.push_back(p->hashes[i]);
            }

            int node;
            int base = LEAVES;
            int level = 1;
            int index;
            for (int i = 0; i < logb(LEAVES, FANOUT); i++) {
                HASH_FUNCTION(values, FANOUT * i, FANOUT, res);
                node = base + (int)indexes.at(0)/(pow(FANOUT,level));
                int n = 0;
                index = values.size() - i;

                while (indexes.at(index) < node) {
                    values.push_back(p->hashes[index++]);
                    n++;
                }
                values.push_back(res);
                while(FANOUT - 1 - n > 0) {
                    values.push_back(p->hashes[index++]);
                    n++;
                }

                base = base + LEAVES/pow(FANOUT, level++);
            }

            return res;
        }

        bool verify(Proof p, Hash challenge) {
            std::vector<int> indexes = get_path_indexes(challenge % LEAVES);
            Proof d = decode(p, indexes);
            Hash root = compute_root(&d, indexes);

            return root == p.root();
        }

        Hash challenge() {
            return Hash();
        }

        protected:
        std::set<Hash> search;
        int conflicts = 0;
        int plots = 0;
    };

}