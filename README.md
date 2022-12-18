# Fully Homomorphic Encryption to Fully Halt the Enemies 

This repository contains implementation and experiment code used to explore ways to prevent backdoor attacks in a fully homomorphically encrypted federated learning environment as part of the completion of a final project for Harvard CS 242.
 
The code is organized across three files: 

1. `simulation.ipynb` provides implementations for two backdoor attacks, secure aggregation schemes, and a federated learning simulation. Additionally, it contains the results gathered and plots generated over the course of our experiments. For additional details on how to run a simulation, see the inline comments. 

2. `fhe-evaluation.py` contains code that performs the actual FHE evaluation of Chebyshev and Minimax polynomials, using a Python wrapper of the Microsoft SEAL framework. This was used to generate our performance and FHE accuracy results. 

3. `approximation_functions.ipynb` contains a simple library for generating Chebyshev and Minimax approximations of our target aggregation functions. After experimentation, the Chebyshev section was incorporated into `simulation.ipynb`.
