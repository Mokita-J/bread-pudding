#include "por.hpp"
#include <iostream>
#include <chrono>

int main(int argc, char** argv) {
  if (argc < 1) {
    std::cout << "Please enter a file name to plot.\n";
    return 0;
  }
    por::PoRepT<32, merkle::sha256, 2, 64> p;

    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    p.plot(argv[1]);
    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();

    std::cout << "Conflicts: " << p.get_conflicts() << std::endl;
    std::cout << "Plots: " << p.get_plots() << std::endl;
    std::cout << "Execution time = " << std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count() << "[ms]" << std::endl;
    // auto c = p.challenge();
    // auto proof = p.generate_proof(c);
    // bool v = p.verify(proof, c);

    // std::cout << v << std::endl;

    // std::cout << proof.quality(c) << std::endl;

}