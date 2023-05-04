#include "por.hpp"
#include <iostream>

int main(int argc, char** argv) {
  if (argc < 1) {
    std::cout << "Please enter a file name to plot.\n";
    return 0;
  }
    por::PoRepT<32, merkle::sha256, 2, 64> p;
    p.plot(argv[1]);
    auto c = p.challenge();
    auto proof = p.generate_proof(c);
    bool v = p.verify(proof, c);

    std::cout << v << std::endl;

    std::cout << proof.quality(c) << std::endl;
  
}